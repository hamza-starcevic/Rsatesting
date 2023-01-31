#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <iostream>
#include <string>
#include <algorithm>

using namespace std;

string base64UrlEncode(const string &input) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input.c_str(), input.length());
    //BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    string output(bptr->data, bptr->length);
    output = output.substr(0, output.length() - 1);
    replace(output.begin(), output.end(), '+', '-');
    replace(output.begin(), output.end(), '/', '_');

    BIO_free_all(b64);
    return output;
}

string base64UrlDecode(const string &input) {
    string output(input);
    replace(output.begin(), output.end(), '-', '+');
    replace(output.begin(), output.end(), '_', '/');
    output.append((4 - (output.length() % 4)) % 4, '=');

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(output.c_str(), output.length());
    b64 = BIO_push(b64, bmem);

    char *decoded = new char[output.length()];
    int decodedLength = BIO_read(b64, decoded, output.length());

    output = string(decoded, decodedLength);

    BIO_free_all(b64);
    return output;
}

string signJWT(const string &header, const string &payload, EVP_PKEY *privateKey) {
    string encodedHeader = base64UrlEncode(header);
    string encodedPayload = base64UrlEncode(payload);

    string input = encodedHeader + "." + encodedPayload;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hashLength;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hashLength);

    EVP_PKEY_CTX *pkeyCtx = NULL;

    EVP_SignInit(mdctx,  EVP_sha256());
    EVP_PKEY_sign_init(pkeyCtx);

    size_t signatureLength = EVP_PKEY_size(privateKey);
    auto *signature = new unsigned char[signatureLength];

    EVP_SignUpdate(mdctx, hash, hashLength);
    EVP_SignFinal(mdctx, signature, reinterpret_cast<unsigned int *>(&signatureLength), privateKey);

    string encodedSignature = base64UrlEncode(string(reinterpret_cast<char *>(signature), signatureLength));
    string jwt = input + "." + encodedSignature;

    delete[] signature;
    EVP_MD_CTX_destroy(mdctx);
    return jwt;
}

int main () {
    EVP_PKEY *privateKey = NULL;
    FILE *privateKeyFile = fopen("private.pem", "r");
    PEM_read_PrivateKey(privateKeyFile, &privateKey, NULL, NULL);
    fclose(privateKeyFile);

    string jwt = signJWT("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", "{\"iss\":\"test\",\"sub\":\"test\",\"aud\":\"test\",\"exp\":9999999999,\"iat\":9999999999}", privateKey);

    cout << jwt << endl;

    return 0;
}