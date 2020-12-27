#include <iostream>
#include <vector>
#include "wrapper.hpp"

using namespace std;
using namespace rust::cxxbridge1;
using namespace challenge_bypass_ristretto;

int main() {
  // Server setup

  const Box<SigningKey> sKey = generate_signing_key();
  Box<PublicKey> pKey = sKey->public_key();

  std::string base64_pkey = std::string(pKey->encode_base64());

  // Signing

  // client prepares a random token and blinding scalar
  Box<Token> tok = generate_token();
  // client stores the original token
  std::string base64_tok = std::string(tok->encode_base64());
  cout<<"[CLIENT] base64_tok: "<<base64_tok<<"\n";

  // client blinds the token
  Box<BlindedToken> blinded_tok = tok->blind();
  // and sends it to the server
  std::string base64_blinded_tok = std::string(blinded_tok->encode_base64());
  cout<<"[CLIENT] base64_blinded_tok: "<<base64_blinded_tok<<"\n";

  // server decodes it
  Box<BlindedTokenResult> server_blinded_tok = decode_base64_blinded_token(base64_blinded_tok);
  if (!server_blinded_tok->is_ok()) {
    std::string msg = std::string(server_blinded_tok->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }

  // server signs the blinded token 
  Box<SignedTokenResult> server_signed_tok = sKey->sign(server_blinded_tok->unwrap());
  if (!server_signed_tok->is_ok()) {
    std::string msg = std::string(server_signed_tok->error().msg);
    cerr<<"ERROR: signing failed: "<<msg<<"\n";
    return 1;
  }

  std::string base64_signed_tok = std::string(server_signed_tok->unwrap().encode_base64());
  cout<<"[SERVER] base64_signed_tok: "<<base64_signed_tok<<"\n";

  std::vector<std::string> base64_blinded_toks = {base64_blinded_tok};
  Box<BlindedTokensResult> server_blinded_toks = decode_base64_blinded_tokens(base64_blinded_toks);
  if (!server_blinded_toks->is_ok()) {
    std::string msg = std::string(server_blinded_toks->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }

  std::vector<std::string> base64_signed_toks = {base64_signed_tok};
  Box<SignedTokensResult> server_signed_toks = decode_base64_signed_tokens(base64_signed_toks);
  if (!server_signed_toks->is_ok()) {
    std::string msg = std::string(server_signed_toks->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }

  Box<BatchDLEQProofResult> server_batch_proof = sKey->new_batch_dleq_proof(server_blinded_toks->unwrap(), server_signed_toks->unwrap());
  if (!server_batch_proof->is_ok()) {
    std::string msg = std::string(server_batch_proof->error().msg);
    cerr<<"ERROR: creating batch proof failed: "<<msg<<"\n";
    return 1;
  }

  std::string base64_batch_proof = std::string(server_batch_proof->unwrap().encode_base64());
  cout<<"[SERVER] base64_batch_proof: "<<base64_batch_proof<<"\n";

  Box<BatchDLEQProofResult> batch_proof = decode_base64_batch_dleq_proof(base64_batch_proof);
  if (!batch_proof->is_ok()) {
    std::string msg = std::string(batch_proof->error().msg);
    cerr<<"ERROR: deserializing batch proof failed: "<<msg<<"\n";
    return 1;
  }

  Box<PublicKeyResult> client_pkey = decode_base64_public_key(base64_pkey);
  if (!client_pkey->is_ok()) {
    std::string msg = std::string(client_pkey->error().msg);
    cerr<<"ERROR: deserializing public key failed: "<<msg<<"\n";
    return 1;
  }

  if (!batch_proof->unwrap().verify(server_blinded_toks->unwrap(), server_signed_toks->unwrap(), client_pkey->unwrap()).is_ok()) {
    cerr<<"ERROR: verifying proof failed: "<<"\n";
    return 1;
  }

   std::vector<std::string> base64_toks = {base64_tok};
  Box<TokensResult> restored_toks = decode_base64_tokens(base64_toks);
  if (!restored_toks->is_ok()) {
    std::string msg = std::string(restored_toks->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }

  Box<UnblindedTokensResult> unblinded_toks = batch_proof->unwrap().verify_and_unblind(restored_toks->unwrap(), server_blinded_toks->unwrap(), server_signed_toks->unwrap(), client_pkey->unwrap());
  if (!unblinded_toks->is_ok()) {
    std::string msg = std::string(unblinded_toks->error().msg);
    cerr<<"ERROR: verifying proof and unblinding failed: "<<msg<<"\n";
    return 1;
  }

  // client stores the unblinded tokens

  std::vector<std::string> base64_unblinded_toks;
  for (const UnblindedToken& unblinded_tok : unblinded_toks->unwrap().as_vec()) {
    std::string base64_unblinded_tok = std::string(unblinded_tok.encode_base64());
    cout<<"[CLIENT] base64_unblinded_tok: "<<base64_unblinded_tok<<"\n";
    base64_unblinded_toks.push_back(base64_unblinded_tok);
  }

  // Redemption 

  // client later restore the next unblinded token in order to redeem
  Box<UnblindedTokenResult> restored_unblinded_tok = decode_base64_unblinded_token(base64_unblinded_toks[0]);
  if (!restored_unblinded_tok->is_ok()) {
    std::string msg = std::string(restored_unblinded_tok->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }

  // client derives the shared key from the unblinded token
  Box<VerificationKey> client_vKey = restored_unblinded_tok->unwrap().derive_verification_key();
  // client signs a message using the shared key
  std::string message = std::string("\0test message", 13);
  Box<VerificationSignature> client_sig = client_vKey->sign(message);
  // client sends the token preimage, signature and message to the server
  std::string base64_token_preimage = std::string(restored_unblinded_tok->unwrap().preimage().encode_base64());
  cout<<"[CLIENT] base64_token_preimage: "<<base64_token_preimage<<"\n";
  std::string base64_signature = std::string(client_sig->encode_base64());
  cout<<"[CLIENT] base64_signature: "<<base64_signature<<"\n";

  // server decodes the token preimage and signature
  Box<TokenPreimageResult> server_preimage = decode_base64_token_preimage(base64_token_preimage);
  if (!server_preimage->is_ok()) {
    std::string msg = std::string(server_preimage->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }

  Box<VerificationSignatureResult> server_sig = decode_base64_verification_signature(base64_signature);
  if (!server_sig->is_ok()) {
    std::string msg = std::string(server_sig->error().msg);
    cerr<<"ERROR: deserialization failed: "<<msg<<"\n";
    return 1;
  }


  // server derives the unblinded token using it's key and the clients token preimage
  Box<UnblindedToken> server_unblinded_tok = sKey->rederive_unblinded_token(server_preimage->unwrap());
  // server derives the shared key from the unblinded token
  Box<VerificationKey> server_vKey = server_unblinded_tok->derive_verification_key();

  // The server verifies the client signature
  if (server_vKey->verify(server_sig->unwrap(), message)) {
    cout<<"sigs equal\n";
  }

  if (server_vKey->verify(server_sig->unwrap(), std::string("\0foobar", 7))) {
    cerr<<"ERROR: wrong sigs equal\n";
    return 1;
  }

  Box<SigningKey> sKey2 = generate_signing_key();
  Box<UnblindedToken> server_unblinded_tok2 = sKey2->rederive_unblinded_token(server_preimage->unwrap());
  Box<VerificationKey> server_vKey2 = server_unblinded_tok2->derive_verification_key();

  if (server_vKey2->verify(server_sig->unwrap(), message)) {
    cerr<<"ERROR: wrong sigs equal\n";
    return 1;
  }
}
