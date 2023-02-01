#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <fstream>

std::string base64encode(const std::string& str) {

    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, str.c_str(), str.length());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    std::string ret(bptr->length, 0);
    std::copy(bptr->data, bptr->data + bptr->length - 1, ret.begin());

    BIO_free_all(b64);

    // replace + with - and / with _
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    // remove trailing =
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());


    return ret;
}

int main() {
    std::string header = "{\n"
                      "  \"alg\": \"PS256\",\n"
                      "  \"typ\": \"JWT\"\n"
                      "}";
    std::string payload = "{\n"
                       "  \"iss\": \"https://example.com\",\n"
                       "  \"sub\": \"1234567890\",\n"
                       "  \"aud\": \"https://example.com\",\n"
                       "  \"exp\": 1516239022,\n"
                       "  \"iat\": 1516239022\n"
                       "}";
    std::string encodedHeader = base64encode(header) ;
    std::string encodedPayload = base64encode(payload) ;
    std::string encodedHeaderPayload = encodedHeader + "." + encodedPayload;

    std::string  input = encodedHeader + "." + encodedPayload;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hashLength;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hashLength);

    EVP_PKEY_CTX *pkeyCtx = NULL;

    EVP_SignInit(mdctx,  EVP_sha256());
    EVP_PKEY_sign_init(pkeyCtx);

    EVP_PKEY *pkey = NULL;
    std::ifstream ifs("private.pem");
    std::string key((std::istreambuf_iterator<char>(ifs)),
                     (std::istreambuf_iterator<char>()));
    BIO *keybio = BIO_new_mem_buf(key.c_str(), -1);
    pkey = PEM_read_bio_PrivateKey(keybio, &pkey, NULL, NULL);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_sign_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    size_t siglen;
    EVP_PKEY_sign(ctx, NULL, &siglen, hash, hashLength);
    unsigned char *sig = (unsigned char *)OPENSSL_malloc(siglen);
    EVP_PKEY_sign(ctx, sig, &siglen, hash, hashLength);
    std::string signature = base64encode(std::string((char *)sig, siglen));
    std::cout << encodedHeaderPayload + "." + signature << std::endl;
    //output it to a file
    std::ofstream outfile ("jwt.txt");
    outfile << encodedHeaderPayload + "." + signature;
    outfile.close();

    return 0;
}


//
//    std::string check_size;
//    //Load the value of private.pem into check_size
//    std::ifstream file("private.pem");
//    std::string str;
//    while (std::getline(file, str))
//    {
//        check_size += str;
//        check_size.push_back('\n');
//    }
//
//
//
//
//
//
//    int signauture_length = check_size.length();
//
//     auto *privateKey = (EVP_PKEY *) check_size.c_str();
//
//    auto *signature = new unsigned char[signauture_length];

//    EVP_SignUpdate(mdctx, hash, hashLength);
//    EVP_SignFinal(mdctx, signature, reinterpret_cast<unsigned int *>(&signauture_length), (EVP_PKEY *) privateKey);
//
//    std::string  encodedSignature = base64encode(std::string (reinterpret_cast<char *>(signature), signauture_length));
//
//
//    std::cout << "Size of signature: " << signauture_length << std::endl;
//    std::cout << encodedHeaderPayload << std::endl;
//    return 0;
//}