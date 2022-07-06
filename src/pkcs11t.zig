const c = @import("std").zig.c_translation;

pub const CK_BYTE = u8;
pub const CK_VERSION = extern struct {
    major: CK_BYTE, // integer portion of version number
    minor: CK_BYTE, // 1/100ths portion of version number
};
pub const CK_VERSION_PTR = ?*CK_VERSION;
pub const CK_BBOOL = CK_BYTE;
pub const CK_ULONG = u32;
pub const CK_UTF8CHAR = CK_BYTE;
pub const CK_NOTIFICATION = CK_ULONG;
pub const CK_FLAGS = CK_ULONG;
pub const CK_USER_TYPE = CK_ULONG;
pub const CK_STATE = CK_ULONG;
pub const CK_OBJECT_CLASS = CK_ULONG;
pub const CK_HW_FEATURE_TYPE = CK_ULONG;
pub const CK_KEY_TYPE = CK_ULONG;
pub const CK_CERTIFICATE_TYPE = CK_ULONG;
pub const CK_ATTRIBUTE_TYPE = CK_ULONG;
pub const CK_MECHANISM_TYPE = CK_ULONG;
pub const CK_RV = CK_ULONG;
pub const CK_SLOT_ID = CK_ULONG;
pub const CK_CHAR = CK_BYTE;
pub const CK_RSA_PKCS_MGF_TYPE = CK_ULONG;
pub const CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG;
pub const CK_X9_42_DH_KDF_TYPE = CK_ULONG;
pub const CK_VOID_PTR_PTR = ?*CK_VOID_PTR;
pub const CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG;
pub const CK_UTF8CHAR_PTR = ?*CK_UTF8CHAR;
pub const CK_ULONG_PTR = ?*CK_ULONG;
pub const CK_SLOT_ID_PTR = ?*CK_SLOT_ID;
pub const CK_SLOT_INFO_PTR = ?*CK_SLOT_INFO;
pub const CK_TOKEN_INFO_PTR = ?*CK_TOKEN_INFO;
pub const CK_SESSION_HANDLE = CK_ULONG;
pub const CK_SESSION_HANDLE_PTR = [*c]CK_SESSION_HANDLE;
pub const CK_NOTIFY = ?fn (CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) callconv(.C) CK_RV;

pub const CK_VOID = enum(c_int) {
    __Variant1,
    __Variant2,
};

pub const CK_INFO = extern struct {
    cryptokiVersion: CK_VERSION,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    libraryDescription: [32]CK_UTF8CHAR,
    libraryVersion: CK_VERSION,
};

pub const CK_SLOT_INFO = extern struct {
    slotDescription: [64]CK_UTF8CHAR,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
};

pub const CK_TOKEN_INFO = extern struct {
    label: [32]CK_UTF8CHAR,
    manufacturerID: [32]CK_UTF8CHAR,
    model: [16]CK_UTF8CHAR,
    serialNumber: [16]CK_CHAR,
    flags: CK_FLAGS,
    ulMaxSessionCount: CK_ULONG,
    ulSessionCount: CK_ULONG,
    ulMaxRwSessionCount: CK_ULONG,
    ulRwSessionCount: CK_ULONG,
    ulMaxPinLen: CK_ULONG,
    ulMinPinLen: CK_ULONG,
    ulTotalPublicMemory: CK_ULONG,
    ulFreePublicMemory: CK_ULONG,
    ulTotalPrivateMemory: CK_ULONG,
    ulFreePrivateMemory: CK_ULONG,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
    utcTime: [16]CK_CHAR,
};

pub const CK_SESSION_INFO = extern struct {
    slotID: CK_SLOT_ID,
    state: CK_STATE,
    flags: CK_FLAGS,
    ulDeviceError: CK_ULONG,
};

pub const CK_INFO_PTR = ?*CK_INFO;
pub const CK_SESSION_INFO_PTR = *CK_SESSION_INFO;
pub const CK_OBJECT_HANDLE_PTR = *CK_OBJECT_HANDLE;
pub const CK_OBJECT_CLASS_PTR = *CK_OBJECT_CLASS;
pub const CK_ATTRIBUTE = extern struct {
    type: CK_ATTRIBUTE_TYPE,
    pValue: CK_VOID_PTR,
    ulValueLen: CK_ULONG,
};
pub const CK_ATTRIBUTE_PTR = *CK_ATTRIBUTE;
pub const CK_DATE = extern struct {
    year: [4]CK_CHAR,
    month: [2]CK_CHAR,
    day: [2]CK_CHAR,
};

pub const CK_MECHANISM_TYPE_PTR = *CK_MECHANISM_TYPE;
pub const CK_MECHANISM = extern struct {
    mechanism: CK_MECHANISM_TYPE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
};
pub const CK_MECHANISM_PTR = *CK_MECHANISM;
pub const CK_MECHANISM_INFO = extern struct {
    ulMinKeySize: CK_ULONG,
    ulMaxKeySize: CK_ULONG,
    flags: CK_FLAGS,
};
pub const CK_MECHANISM_INFO_PTR = *CK_MECHANISM_INFO;
pub const CK_CREATEMUTEX = ?fn (CK_VOID_PTR_PTR) callconv(.C) CK_RV;
pub const CK_DESTROYMUTEX = ?fn (CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_LOCKMUTEX = ?fn (CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_UNLOCKMUTEX = ?fn (CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_C_INITIALIZE_ARGS = extern struct {
    CreateMutex: CK_CREATEMUTEX,
    DestroyMutex: CK_DESTROYMUTEX,
    LockMutex: CK_LOCKMUTEX,
    UnlockMutex: CK_UNLOCKMUTEX,
    flags: CK_FLAGS,
    pReserved: CK_VOID_PTR,
};
pub const CK_VOID_PTR = ?*CK_VOID;
pub const CK_BYTE_PTR = ?*CK_BYTE;
pub const CK_OBJECT_HANDLE = CK_ULONG;
pub const CK_X2RATCHET_KDF_TYPE = CK_ULONG;
pub const CK_X3DH_KDF_TYPE = CK_ULONG;
pub const CK_X2RATCHET_KDF_TYPE_PTR = CK_X2RATCHET_KDF_TYPE;

pub const CK_ECDH1_DERIVE_PARAMS = extern struct {
    kdf: CK_EC_KDF_TYPE,
    ulSharedDataLen: CK_ULONG,
    pSharedData: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
};

pub const CK_RSA_PKCS_OAEP_PARAMS = extern struct {
    hashAlg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    source: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
    pSourceData: CK_VOID_PTR,
    ulSourceDataLen: CK_ULONG,
};

// X3dh, ratchet
pub const CK_X3DH_INITIATE_PARAMS = extern struct {
    kdf: CK_X3DH_KDF_TYPE,
    pPeer_identity: CK_OBJECT_HANDLE,
    pPeer_prekey: CK_OBJECT_HANDLE,
    pPrekey_signature: CK_BYTE_PTR,
    pOnetime_key: CK_BYTE_PTR,
    pOwn_identity: CK_OBJECT_HANDLE,
    pOwn_ephemeral: CK_OBJECT_HANDLE,
};

pub const CK_X3DH_RESPOND_PARAMS = extern struct {
    kdf: CK_X3DH_KDF_TYPE,
    pIdentity_id: CK_BYTE_PTR,
    pPrekey_id: CK_BYTE_PTR,
    pOnetime_id: CK_BYTE_PTR,
    pInitiator_identity: CK_OBJECT_HANDLE,
    pInitiator_ephemeral: CK_BYTE_PTR,
};

pub const CK_X2RATCHET_INITIALIZE_PARAMS = extern struct {
    sk: CK_BYTE_PTR,
    peer_public_prekey: CK_OBJECT_HANDLE,
    peer_public_identity: CK_OBJECT_HANDLE,
    own_public_identity: CK_OBJECT_HANDLE,
    bEncryptedHeader: CK_BBOOL,
    eCurve: CK_ULONG,
    aeadMechanism: CK_MECHANISM_TYPE,
    kdfMechanism: CK_X2RATCHET_KDF_TYPE,
};

pub const CK_X2RATCHET_INITIALIZE_PARAMS_PTR = ?*CK_X2RATCHET_INITIALIZE_PARAMS;

pub const CK_X2RATCHET_RESPOND_PARAMS = extern struct {
    sk: CK_BYTE_PTR,
    own_prekey: CK_OBJECT_HANDLE,
    initiator_identity: CK_OBJECT_HANDLE,
    own_public_identity: CK_OBJECT_HANDLE,
    bEncryptedHeader: CK_BBOOL,
    eCurve: CK_ULONG,
    aeadMechanism: CK_MECHANISM_TYPE,
    kdfMechanism: CK_X2RATCHET_KDF_TYPE,
};
pub const CK_X2RATCHET_RESPOND_PARAMS_PTR = ?*CK_X2RATCHET_RESPOND_PARAMS;

pub const CK_XEDDSA_HASH_TYPE = CK_ULONG;
pub const CK_XEDDSA_HASH_TYPE_PTR = ?*CK_XEDDSA_HASH_TYPE;

// XEDDSA
pub const CK_XEDDSA_PARAMS = extern struct {
    hash: CK_XEDDSA_HASH_TYPE,
};
pub const CK_XEDDSA_PARAMS_PTR = ?*CK_XEDDSA_PARAMS;

pub const CK_HKDF_PARAMS = extern struct {
    bExtract: CK_BBOOL,
    bExpand: CK_BBOOL,
    prfHashMechanism: CK_MECHANISM_TYPE,
    ulSaltType: CK_ULONG,
    pSalt: CK_BYTE_PTR,
    ulSaltLen: CK_ULONG,
    hSaltKey: CK_OBJECT_HANDLE,
    pInfo: CK_BYTE_PTR,
    ulInfoLen: CK_ULONG,
};

pub const CK_C_INITIALIZE_ARGS_PTR = ?*CK_C_INITIALIZE_ARGS;
pub const CK_RSA_PKCS_MGF_TYPE_PTR = ?*CK_RSA_PKCS_MGF_TYPE;
pub const CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR = *CK_RSA_PKCS_OAEP_SOURCE_TYPE;
pub const CK_RSA_PKCS_OAEP_PARAMS_PTR = *CK_RSA_PKCS_OAEP_PARAMS;
pub const CK_RSA_PKCS_PSS_PARAMS = extern struct {
    hashAlg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    sLen: CK_ULONG,
};

pub const CK_RSA_PKCS_PSS_PARAMS_PTR = *CK_RSA_PKCS_PSS_PARAMS;
pub const CK_EC_KDF_TYPE = CK_ULONG;
pub const CK_ECDH1_DERIVE_PARAMS_PTR = *CK_ECDH1_DERIVE_PARAMS;
pub const CK_ECDH2_DERIVE_PARAMS = extern struct {
    kdf: CK_EC_KDF_TYPE,
    ulSharedDataLen: CK_ULONG,
    pSharedData: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
    ulPrivateDataLen: CK_ULONG,
    hPrivateData: CK_OBJECT_HANDLE,
    ulPublicDataLen2: CK_ULONG,
    pPublicData2: CK_BYTE_PTR,
};
pub const CK_ECDH2_DERIVE_PARAMS_PTR = *CK_ECDH2_DERIVE_PARAMS;
pub const CK_ECMQV_DERIVE_PARAMS = extern struct {
    kdf: CK_EC_KDF_TYPE,
    ulSharedDataLen: CK_ULONG,
    pSharedData: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
    ulPrivateDataLen: CK_ULONG,
    hPrivateData: CK_OBJECT_HANDLE,
    ulPublicDataLen2: CK_ULONG,
    pPublicData2: CK_BYTE_PTR,
    publicKey: CK_OBJECT_HANDLE,
};
pub const CK_ECMQV_DERIVE_PARAMS_PTR = *CK_ECMQV_DERIVE_PARAMS;
pub const CK_X9_42_DH_KDF_TYPE_PTR = *CK_X9_42_DH_KDF_TYPE;
pub const CK_X9_42_DH1_DERIVE_PARAMS = extern struct {
    kdf: CK_X9_42_DH_KDF_TYPE,
    ulOtherInfoLen: CK_ULONG,
    pOtherInfo: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
};
pub const CK_X9_42_DH1_DERIVE_PARAMS_PTR = *CK_X9_42_DH1_DERIVE_PARAMS;
pub const CK_X9_42_DH2_DERIVE_PARAMS = extern struct {
    kdf: CK_X9_42_DH_KDF_TYPE,
    ulOtherInfoLen: CK_ULONG,
    pOtherInfo: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
    ulPrivateDataLen: CK_ULONG,
    hPrivateData: CK_OBJECT_HANDLE,
    ulPublicDataLen2: CK_ULONG,
    pPublicData2: CK_BYTE_PTR,
};
pub const CK_X9_42_DH2_DERIVE_PARAMS_PTR = *CK_X9_42_DH2_DERIVE_PARAMS;
pub const CK_X9_42_MQV_DERIVE_PARAMS = extern struct {
    kdf: CK_X9_42_DH_KDF_TYPE,
    ulOtherInfoLen: CK_ULONG,
    pOtherInfo: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
    ulPrivateDataLen: CK_ULONG,
    hPrivateData: CK_OBJECT_HANDLE,
    ulPublicDataLen2: CK_ULONG,
    pPublicData2: CK_BYTE_PTR,
    publicKey: CK_OBJECT_HANDLE,
};
pub const CK_X9_42_MQV_DERIVE_PARAMS_PTR = *CK_X9_42_MQV_DERIVE_PARAMS;
pub const CK_KEA_DERIVE_PARAMS = extern struct {
    isSender: CK_BBOOL,
    ulRandomLen: CK_ULONG,
    pRandomA: CK_BYTE_PTR,
    pRandomB: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
};
pub const CK_KEA_DERIVE_PARAMS_PTR = *CK_KEA_DERIVE_PARAMS;
pub const CK_RC2_PARAMS = CK_ULONG;
pub const CK_RC2_PARAMS_PTR = *CK_RC2_PARAMS;
pub const CK_RC2_CBC_PARAMS = extern struct {
    ulEffectiveBits: CK_ULONG,
    iv: [8]CK_BYTE,
};
pub const CK_RC2_CBC_PARAMS_PTR = *CK_RC2_CBC_PARAMS;
pub const CK_RC2_MAC_GENERAL_PARAMS = extern struct {
    ulEffectiveBits: CK_ULONG,
    ulMacLength: CK_ULONG,
};
pub const CK_RC2_MAC_GENERAL_PARAMS_PTR = *CK_RC2_MAC_GENERAL_PARAMS;
pub const CK_RC5_PARAMS = extern struct {
    ulWordsize: CK_ULONG,
    ulRounds: CK_ULONG,
};
pub const CK_RC5_PARAMS_PTR = *CK_RC5_PARAMS;
pub const CK_RC5_CBC_PARAMS = extern struct {
    ulWordsize: CK_ULONG,
    ulRounds: CK_ULONG,
    pIv: CK_BYTE_PTR,
    ulIvLen: CK_ULONG,
};
pub const CK_RC5_CBC_PARAMS_PTR = *CK_RC5_CBC_PARAMS;
pub const CK_RC5_MAC_GENERAL_PARAMS = extern struct {
    ulWordsize: CK_ULONG,
    ulRounds: CK_ULONG,
    ulMacLength: CK_ULONG,
};
pub const CK_RC5_MAC_GENERAL_PARAMS_PTR = *CK_RC5_MAC_GENERAL_PARAMS;
pub const CK_MAC_GENERAL_PARAMS = CK_ULONG;
pub const CK_MAC_GENERAL_PARAMS_PTR = *CK_MAC_GENERAL_PARAMS;
pub const CK_DES_CBC_ENCRYPT_DATA_PARAMS = extern struct {
    iv: [8]CK_BYTE,
    pData: CK_BYTE_PTR,
    length: CK_ULONG,
};
pub const CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR = *CK_DES_CBC_ENCRYPT_DATA_PARAMS;
pub const CK_AES_CBC_ENCRYPT_DATA_PARAMS = extern struct {
    iv: [16]CK_BYTE,
    pData: CK_BYTE_PTR,
    length: CK_ULONG,
};
pub const CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR = *CK_AES_CBC_ENCRYPT_DATA_PARAMS;
pub const CK_SKIPJACK_PRIVATE_WRAP_PARAMS = extern struct {
    ulPasswordLen: CK_ULONG,
    pPassword: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
    ulPAndGLen: CK_ULONG,
    ulQLen: CK_ULONG,
    ulRandomLen: CK_ULONG,
    pRandomA: CK_BYTE_PTR,
    pPrimeP: CK_BYTE_PTR,
    pBaseG: CK_BYTE_PTR,
    pSubprimeQ: CK_BYTE_PTR,
};
pub const CK_SKIPJACK_PRIVATE_WRAP_PARAMS_PTR = *CK_SKIPJACK_PRIVATE_WRAP_PARAMS;
pub const CK_SKIPJACK_RELAYX_PARAMS = extern struct {
    ulOldWrappedXLen: CK_ULONG,
    pOldWrappedX: CK_BYTE_PTR,
    ulOldPasswordLen: CK_ULONG,
    pOldPassword: CK_BYTE_PTR,
    ulOldPublicDataLen: CK_ULONG,
    pOldPublicData: CK_BYTE_PTR,
    ulOldRandomLen: CK_ULONG,
    pOldRandomA: CK_BYTE_PTR,
    ulNewPasswordLen: CK_ULONG,
    pNewPassword: CK_BYTE_PTR,
    ulNewPublicDataLen: CK_ULONG,
    pNewPublicData: CK_BYTE_PTR,
    ulNewRandomLen: CK_ULONG,
    pNewRandomA: CK_BYTE_PTR,
};
pub const CK_SKIPJACK_RELAYX_PARAMS_PTR = *CK_SKIPJACK_RELAYX_PARAMS;
pub const CK_PBE_PARAMS = extern struct {
    pInitVector: CK_BYTE_PTR,
    pPassword: CK_UTF8CHAR_PTR,
    ulPasswordLen: CK_ULONG,
    pSalt: CK_BYTE_PTR,
    ulSaltLen: CK_ULONG,
    ulIteration: CK_ULONG,
};
pub const CK_PBE_PARAMS_PTR = *CK_PBE_PARAMS;
pub const CK_KEY_WRAP_SET_OAEP_PARAMS = extern struct {
    bBC: CK_BYTE,
    pX: CK_BYTE_PTR,
    ulXLen: CK_ULONG,
};
pub const CK_KEY_WRAP_SET_OAEP_PARAMS_PTR = *CK_KEY_WRAP_SET_OAEP_PARAMS;
pub const CK_SSL3_RANDOM_DATA = extern struct {
    pClientRandom: CK_BYTE_PTR,
    ulClientRandomLen: CK_ULONG,
    pServerRandom: CK_BYTE_PTR,
    ulServerRandomLen: CK_ULONG,
};
pub const CK_SSL3_MASTER_KEY_DERIVE_PARAMS = extern struct {
    RandomInfo: CK_SSL3_RANDOM_DATA,
    pVersion: CK_VERSION_PTR,
};
pub const CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR = *CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
pub const CK_SSL3_KEY_MAT_OUT = extern struct {
    hClientMacSecret: CK_OBJECT_HANDLE,
    hServerMacSecret: CK_OBJECT_HANDLE,
    hClientKey: CK_OBJECT_HANDLE,
    hServerKey: CK_OBJECT_HANDLE,
    pIVClient: CK_BYTE_PTR,
    pIVServer: CK_BYTE_PTR,
};
pub const CK_SSL3_KEY_MAT_OUT_PTR = *CK_SSL3_KEY_MAT_OUT;
pub const CK_SSL3_KEY_MAT_PARAMS = extern struct {
    ulMacSizeInBits: CK_ULONG,
    ulKeySizeInBits: CK_ULONG,
    ulIVSizeInBits: CK_ULONG,
    bIsExport: CK_BBOOL,
    RandomInfo: CK_SSL3_RANDOM_DATA,
    pReturnedKeyMaterial: CK_SSL3_KEY_MAT_OUT_PTR,
};
pub const CK_SSL3_KEY_MAT_PARAMS_PTR = *CK_SSL3_KEY_MAT_PARAMS;
pub const CK_TLS_PRF_PARAMS = extern struct {
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
    pLabel: CK_BYTE_PTR,
    ulLabelLen: CK_ULONG,
    pOutput: CK_BYTE_PTR,
    pulOutputLen: CK_ULONG_PTR,
};
pub const CK_TLS_PRF_PARAMS_PTR = *CK_TLS_PRF_PARAMS;
pub const CK_WTLS_RANDOM_DATA = extern struct {
    pClientRandom: CK_BYTE_PTR,
    ulClientRandomLen: CK_ULONG,
    pServerRandom: CK_BYTE_PTR,
    ulServerRandomLen: CK_ULONG,
};
pub const CK_WTLS_RANDOM_DATA_PTR = *CK_WTLS_RANDOM_DATA;
pub const CK_WTLS_MASTER_KEY_DERIVE_PARAMS = extern struct {
    DigestMechanism: CK_MECHANISM_TYPE,
    RandomInfo: CK_WTLS_RANDOM_DATA,
    pVersion: CK_BYTE_PTR,
};
pub const CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR = *CK_WTLS_MASTER_KEY_DERIVE_PARAMS;
pub const CK_WTLS_PRF_PARAMS = extern struct {
    DigestMechanism: CK_MECHANISM_TYPE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
    pLabel: CK_BYTE_PTR,
    ulLabelLen: CK_ULONG,
    pOutput: CK_BYTE_PTR,
    pulOutputLen: CK_ULONG_PTR,
};
pub const CK_WTLS_PRF_PARAMS_PTR = *CK_WTLS_PRF_PARAMS;
pub const CK_WTLS_KEY_MAT_OUT = extern struct {
    hMacSecret: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pIV: CK_BYTE_PTR,
};
pub const CK_WTLS_KEY_MAT_OUT_PTR = *CK_WTLS_KEY_MAT_OUT;
pub const CK_WTLS_KEY_MAT_PARAMS = extern struct {
    DigestMechanism: CK_MECHANISM_TYPE,
    ulMacSizeInBits: CK_ULONG,
    ulKeySizeInBits: CK_ULONG,
    ulIVSizeInBits: CK_ULONG,
    ulSequenceNumber: CK_ULONG,
    bIsExport: CK_BBOOL,
    RandomInfo: CK_WTLS_RANDOM_DATA,
    pReturnedKeyMaterial: CK_WTLS_KEY_MAT_OUT_PTR,
};
pub const CK_WTLS_KEY_MAT_PARAMS_PTR = *CK_WTLS_KEY_MAT_PARAMS;
pub const CK_CMS_SIG_PARAMS = extern struct {
    certificateHandle: CK_OBJECT_HANDLE,
    pSigningMechanism: CK_MECHANISM_PTR,
    pDigestMechanism: CK_MECHANISM_PTR,
    pContentType: CK_UTF8CHAR_PTR,
    pRequestedAttributes: CK_BYTE_PTR,
    ulRequestedAttributesLen: CK_ULONG,
    pRequiredAttributes: CK_BYTE_PTR,
    ulRequiredAttributesLen: CK_ULONG,
};
pub const CK_CMS_SIG_PARAMS_PTR = *CK_CMS_SIG_PARAMS;
pub const CK_KEY_DERIVATION_STRING_DATA = extern struct {
    pData: CK_BYTE_PTR,
    ulLen: CK_ULONG,
};
pub const CK_KEY_DERIVATION_STRING_DATA_PTR = *CK_KEY_DERIVATION_STRING_DATA;
pub const CK_EXTRACT_PARAMS = CK_ULONG;
pub const CK_EXTRACT_PARAMS_PTR = *CK_EXTRACT_PARAMS;
pub const CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG;
pub const CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR = *CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;
pub const CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR = *CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;
pub const CK_PKCS5_PBKD2_PARAMS = extern struct {
    saltSource: CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE,
    pSaltSourceData: CK_VOID_PTR,
    ulSaltSourceDataLen: CK_ULONG,
    iterations: CK_ULONG,
    prf: CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE,
    pPrfData: CK_VOID_PTR,
    ulPrfDataLen: CK_ULONG,
    pPassword: CK_UTF8CHAR_PTR,
    ulPasswordLen: CK_ULONG_PTR,
};
pub const CK_PKCS5_PBKD2_PARAMS_PTR = *CK_PKCS5_PBKD2_PARAMS;
pub const CK_PKCS5_PBKD2_PARAMS2 = extern struct {
    saltSource: CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE,
    pSaltSourceData: CK_VOID_PTR,
    ulSaltSourceDataLen: CK_ULONG,
    iterations: CK_ULONG,
    prf: CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE,
    pPrfData: CK_VOID_PTR,
    ulPrfDataLen: CK_ULONG,
    pPassword: CK_UTF8CHAR_PTR,
    ulPasswordLen: CK_ULONG,
};
pub const CK_PKCS5_PBKD2_PARAMS2_PTR = *CK_PKCS5_PBKD2_PARAMS2;
pub const CK_OTP_PARAM_TYPE = CK_ULONG;
pub const CK_PARAM_TYPE = CK_OTP_PARAM_TYPE;
pub const CK_OTP_PARAM = extern struct {
    type: CK_OTP_PARAM_TYPE,
    pValue: CK_VOID_PTR,
    ulValueLen: CK_ULONG,
};
pub const CK_OTP_PARAM_PTR = *CK_OTP_PARAM;
pub const CK_OTP_PARAMS = extern struct {
    pParams: CK_OTP_PARAM_PTR,
    ulCount: CK_ULONG,
};
pub const CK_OTP_PARAMS_PTR = *CK_OTP_PARAMS;
pub const CK_OTP_SIGNATURE_INFO = extern struct {
    pParams: CK_OTP_PARAM_PTR,
    ulCount: CK_ULONG,
};
pub const CK_OTP_SIGNATURE_INFO_PTR = *CK_OTP_SIGNATURE_INFO;
pub const CK_KIP_PARAMS = extern struct {
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
};
pub const CK_KIP_PARAMS_PTR = *CK_KIP_PARAMS;
pub const CK_AES_CTR_PARAMS = extern struct {
    ulCounterBits: CK_ULONG,
    cb: [16]CK_BYTE,
};
pub const CK_AES_CTR_PARAMS_PTR = *CK_AES_CTR_PARAMS;
pub const CK_GCM_PARAMS = extern struct {
    pIv: CK_BYTE_PTR,
    ulIvLen: CK_ULONG,
    ulIvBits: CK_ULONG,
    pAAD: CK_BYTE_PTR,
    ulAADLen: CK_ULONG,
    ulTagBits: CK_ULONG,
};
pub const CK_GCM_PARAMS_PTR = *CK_GCM_PARAMS;
pub const CK_CCM_PARAMS = extern struct {
    ulDataLen: CK_ULONG,
    pNonce: CK_BYTE_PTR,
    ulNonceLen: CK_ULONG,
    pAAD: CK_BYTE_PTR,
    ulAADLen: CK_ULONG,
    ulMACLen: CK_ULONG,
};
pub const CK_CCM_PARAMS_PTR = *CK_CCM_PARAMS;
pub const CK_AES_GCM_PARAMS = extern struct {
    pIv: CK_BYTE_PTR,
    ulIvLen: CK_ULONG,
    ulIvBits: CK_ULONG,
    pAAD: CK_BYTE_PTR,
    ulAADLen: CK_ULONG,
    ulTagBits: CK_ULONG,
};
pub const CK_AES_GCM_PARAMS_PTR = *CK_AES_GCM_PARAMS;
pub const CK_AES_CCM_PARAMS = extern struct {
    ulDataLen: CK_ULONG,
    pNonce: CK_BYTE_PTR,
    ulNonceLen: CK_ULONG,
    pAAD: CK_BYTE_PTR,
    ulAADLen: CK_ULONG,
    ulMACLen: CK_ULONG,
};
pub const CK_AES_CCM_PARAMS_PTR = *CK_AES_CCM_PARAMS;
pub const CK_CAMELLIA_CTR_PARAMS = extern struct {
    ulCounterBits: CK_ULONG,
    cb: [16]CK_BYTE,
};
pub const CK_CAMELLIA_CTR_PARAMS_PTR = *CK_CAMELLIA_CTR_PARAMS;
pub const CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS = extern struct {
    iv: [16]CK_BYTE,
    pData: CK_BYTE_PTR,
    length: CK_ULONG,
};
pub const CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR = *CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS;
pub const CK_ARIA_CBC_ENCRYPT_DATA_PARAMS = extern struct {
    iv: [16]CK_BYTE,
    pData: CK_BYTE_PTR,
    length: CK_ULONG,
};
pub const CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR = *CK_ARIA_CBC_ENCRYPT_DATA_PARAMS;
pub const CK_DSA_PARAMETER_GEN_PARAM = extern struct {
    hash: CK_MECHANISM_TYPE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
    ulIndex: CK_ULONG,
};
pub const CK_DSA_PARAMETER_GEN_PARAM_PTR = *CK_DSA_PARAMETER_GEN_PARAM;
pub const CK_ECDH_AES_KEY_WRAP_PARAMS = extern struct {
    ulAESKeyBits: CK_ULONG,
    kdf: CK_EC_KDF_TYPE,
    ulSharedDataLen: CK_ULONG,
    pSharedData: CK_BYTE_PTR,
};
pub const CK_ECDH_AES_KEY_WRAP_PARAMS_PTR = *CK_ECDH_AES_KEY_WRAP_PARAMS;
pub const CK_JAVA_MIDP_SECURITY_DOMAIN = CK_ULONG;
pub const CK_CERTIFICATE_CATEGORY = CK_ULONG;
pub const CK_RSA_AES_KEY_WRAP_PARAMS = extern struct {
    ulAESKeyBits: CK_ULONG,
    pOAEPParams: CK_RSA_PKCS_OAEP_PARAMS_PTR,
};
pub const CK_RSA_AES_KEY_WRAP_PARAMS_PTR = *CK_RSA_AES_KEY_WRAP_PARAMS;
pub const CK_TLS12_MASTER_KEY_DERIVE_PARAMS = extern struct {
    RandomInfo: CK_SSL3_RANDOM_DATA,
    pVersion: CK_VERSION_PTR,
    prfHashMechanism: CK_MECHANISM_TYPE,
};
pub const CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR = *CK_TLS12_MASTER_KEY_DERIVE_PARAMS;
pub const CK_TLS12_KEY_MAT_PARAMS = extern struct {
    ulMacSizeInBits: CK_ULONG,
    ulKeySizeInBits: CK_ULONG,
    ulIVSizeInBits: CK_ULONG,
    bIsExport: CK_BBOOL,
    RandomInfo: CK_SSL3_RANDOM_DATA,
    pReturnedKeyMaterial: CK_SSL3_KEY_MAT_OUT_PTR,
    prfHashMechanism: CK_MECHANISM_TYPE,
};
pub const CK_TLS12_KEY_MAT_PARAMS_PTR = *CK_TLS12_KEY_MAT_PARAMS;
pub const CK_TLS_KDF_PARAMS = extern struct {
    prfMechanism: CK_MECHANISM_TYPE,
    pLabel: CK_BYTE_PTR,
    ulLabelLength: CK_ULONG,
    RandomInfo: CK_SSL3_RANDOM_DATA,
    pContextData: CK_BYTE_PTR,
    ulContextDataLength: CK_ULONG,
};
pub const CK_TLS_KDF_PARAMS_PTR = *CK_TLS_KDF_PARAMS;
pub const CK_TLS_MAC_PARAMS = extern struct {
    prfHashMechanism: CK_MECHANISM_TYPE,
    ulMacLength: CK_ULONG,
    ulServerOrClient: CK_ULONG,
};
pub const CK_TLS_MAC_PARAMS_PTR = *CK_TLS_MAC_PARAMS;
pub const CK_GOSTR3410_DERIVE_PARAMS = extern struct {
    kdf: CK_EC_KDF_TYPE,
    pPublicData: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pUKM: CK_BYTE_PTR,
    ulUKMLen: CK_ULONG,
};
pub const CK_GOSTR3410_DERIVE_PARAMS_PTR = *CK_GOSTR3410_DERIVE_PARAMS;
pub const CK_GOSTR3410_KEY_WRAP_PARAMS = extern struct {
    pWrapOID: CK_BYTE_PTR,
    ulWrapOIDLen: CK_ULONG,
    pUKM: CK_BYTE_PTR,
    ulUKMLen: CK_ULONG,
    hKey: CK_OBJECT_HANDLE,
};
pub const CK_GOSTR3410_KEY_WRAP_PARAMS_PTR = *CK_GOSTR3410_KEY_WRAP_PARAMS;
pub const CK_SEED_CBC_ENCRYPT_DATA_PARAMS = extern struct {
    iv: [16]CK_BYTE,
    pData: CK_BYTE_PTR,
    length: CK_ULONG,
};

pub const CKR_ERROR = error{
    CKR_OK,
    CKR_CANCEL,
    CKR_HOST_MEMORY,
    CKR_SLOT_ID_INVALID,
    CKR_GENERAL_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_ARGUMENTS_BAD,
    CKR_NO_EVENT,
    CKR_NEED_TO_CREATE_THREADS,
    CKR_CANT_LOCK,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ACTION_PROHIBITED,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_NOT_PARALLEL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_KEY_NOT_NEEDED,
    CKR_KEY_CHANGED,
    CKR_KEY_NEEDED,
    CKR_KEY_INDIGESTIBLE,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PIN_INCORRECT,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_EXPIRED,
    CKR_PIN_LOCKED,
    CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_EXISTS,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_SESSION_READ_WRITE_SO_EXISTS,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_NOT_PRESENT,
    CKR_TOKEN_NOT_RECOGNIZED,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TYPE_INVALID,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_TOO_MANY_TYPES,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
    CKR_RANDOM_NO_RNG,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_BUFFER_TOO_SMALL,
    CKR_SAVED_STATE_INVALID,
    CKR_INFORMATION_SENSITIVE,
    CKR_STATE_UNSAVEABLE,
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_MUTEX_BAD,
    CKR_MUTEX_NOT_LOCKED,
    CKR_NEW_PIN_MODE,
    CKR_NEXT_OTP,
    CKR_EXCEEDED_MAX_ITERATIONS,
    CKR_FIPS_SELF_TEST_FAILED,
    CKR_LIBRARY_LOAD_FAILED,
    CKR_PIN_TOO_WEAK,
    CKR_PUBLIC_KEY_INVALID,
    CKR_FUNCTION_REJECTED,
    CKR_VENDOR_DEFINED,
};

pub const CRYPTOKI_VERSION_MAJOR = @as(c_int, 2);
pub const CRYPTOKI_VERSION_MINOR = @as(c_int, 40);
pub const CRYPTOKI_VERSION_AMENDMENT = @as(c_int, 0);
pub const CK_TRUE = @as(c_int, 1);
pub const CK_FALSE = @as(c_int, 0);
pub const FALSE = CK_FALSE;
pub const TRUE = CK_TRUE;
pub const CK_UNAVAILABLE_INFORMATION = ~@as(c_ulong, 0);
pub const CK_EFFECTIVELY_INFINITE = @as(c_ulong, 0);
pub const CK_INVALID_HANDLE = @as(c_ulong, 0);
pub const CKN_SURRENDER = @as(c_ulong, 0);
pub const CKN_OTP_CHANGED = @as(c_ulong, 1);
pub const CKF_TOKEN_PRESENT = @as(c_ulong, 0x00000001);
pub const CKF_REMOVABLE_DEVICE = @as(c_ulong, 0x00000002);
pub const CKF_HW_SLOT = @as(c_ulong, 0x00000004);
pub const CKF_RNG = @as(c_ulong, 0x00000001);
pub const CKF_WRITE_PROTECTED = @as(c_ulong, 0x00000002);
pub const CKF_LOGIN_REQUIRED = @as(c_ulong, 0x00000004);
pub const CKF_USER_PIN_INITIALIZED = @as(c_ulong, 0x00000008);
pub const CKF_RESTORE_KEY_NOT_NEEDED = @as(c_ulong, 0x00000020);
pub const CKF_CLOCK_ON_TOKEN = @as(c_ulong, 0x00000040);
pub const CKF_PROTECTED_AUTHENTICATION_PATH = @as(c_ulong, 0x00000100);
pub const CKF_DUAL_CRYPTO_OPERATIONS = @as(c_ulong, 0x00000200);
pub const CKF_TOKEN_INITIALIZED = @as(c_ulong, 0x00000400);
pub const CKF_SECONDARY_AUTHENTICATION = @as(c_ulong, 0x00000800);
pub const CKF_USER_PIN_COUNT_LOW = @as(c_ulong, 0x00010000);
pub const CKF_USER_PIN_FINAL_TRY = @as(c_ulong, 0x00020000);
pub const CKF_USER_PIN_LOCKED = @as(c_ulong, 0x00040000);
pub const CKF_USER_PIN_TO_BE_CHANGED = @as(c_ulong, 0x00080000);
pub const CKF_SO_PIN_COUNT_LOW = @as(c_ulong, 0x00100000);
pub const CKF_SO_PIN_FINAL_TRY = @as(c_ulong, 0x00200000);
pub const CKF_SO_PIN_LOCKED = @as(c_ulong, 0x00400000);
pub const CKF_SO_PIN_TO_BE_CHANGED = @as(c_ulong, 0x00800000);
pub const CKF_ERROR_STATE = @as(c_ulong, 0x01000000);
pub const CKU_SO = @as(c_ulong, 0);
pub const CKU_USER = @as(c_ulong, 1);
pub const CKU_CONTEXT_SPECIFIC = @as(c_ulong, 2);
pub const CKS_RO_PUBLIC_SESSION = @as(c_ulong, 0);
pub const CKS_RO_USER_FUNCTIONS = @as(c_ulong, 1);
pub const CKS_RW_PUBLIC_SESSION = @as(c_ulong, 2);
pub const CKS_RW_USER_FUNCTIONS = @as(c_ulong, 3);
pub const CKS_RW_SO_FUNCTIONS = @as(c_ulong, 4);
pub const CKF_RW_SESSION = @as(c_ulong, 0x00000002);
pub const CKF_SERIAL_SESSION = @as(c_ulong, 0x00000004);
pub const CKO_DATA = @as(c_ulong, 0x00000000);
pub const CKO_CERTIFICATE = @as(c_ulong, 0x00000001);
pub const CKO_PUBLIC_KEY = @as(c_ulong, 0x00000002);
pub const CKO_PRIVATE_KEY = @as(c_ulong, 0x00000003);
pub const CKO_SECRET_KEY = @as(c_ulong, 0x00000004);
pub const CKO_HW_FEATURE = @as(c_ulong, 0x00000005);
pub const CKO_DOMAIN_PARAMETERS = @as(c_ulong, 0x00000006);
pub const CKO_MECHANISM = @as(c_ulong, 0x00000007);
pub const CKO_OTP_KEY = @as(c_ulong, 0x00000008);
pub const CKO_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CKH_MONOTONIC_COUNTER = @as(c_ulong, 0x00000001);
pub const CKH_CLOCK = @as(c_ulong, 0x00000002);
pub const CKH_USER_INTERFACE = @as(c_ulong, 0x00000003);
pub const CKH_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CKK_RSA = @as(c_ulong, 0x00000000);
pub const CKK_DSA = @as(c_ulong, 0x00000001);
pub const CKK_DH = @as(c_ulong, 0x00000002);
pub const CKK_ECDSA = @as(c_ulong, 0x00000003);
pub const CKK_EC = @as(c_ulong, 0x00000003);
pub const CKK_X9_42_DH = @as(c_ulong, 0x00000004);
pub const CKK_KEA = @as(c_ulong, 0x00000005);
pub const CKK_GENERIC_SECRET = @as(c_ulong, 0x00000010);
pub const CKK_RC2 = @as(c_ulong, 0x00000011);
pub const CKK_RC4 = @as(c_ulong, 0x00000012);
pub const CKK_DES = @as(c_ulong, 0x00000013);
pub const CKK_DES2 = @as(c_ulong, 0x00000014);
pub const CKK_DES3 = @as(c_ulong, 0x00000015);
pub const CKK_CAST = @as(c_ulong, 0x00000016);
pub const CKK_CAST3 = @as(c_ulong, 0x00000017);
pub const CKK_CAST5 = @as(c_ulong, 0x00000018);
pub const CKK_CAST128 = @as(c_ulong, 0x00000018);
pub const CKK_RC5 = @as(c_ulong, 0x00000019);
pub const CKK_IDEA = @as(c_ulong, 0x0000001A);
pub const CKK_SKIPJACK = @as(c_ulong, 0x0000001B);
pub const CKK_BATON = @as(c_ulong, 0x0000001C);
pub const CKK_JUNIPER = @as(c_ulong, 0x0000001D);
pub const CKK_CDMF = @as(c_ulong, 0x0000001E);
pub const CKK_AES = @as(c_ulong, 0x0000001F);
pub const CKK_BLOWFISH = @as(c_ulong, 0x00000020);
pub const CKK_TWOFISH = @as(c_ulong, 0x00000021);
pub const CKK_SECURID = @as(c_ulong, 0x00000022);
pub const CKK_HOTP = @as(c_ulong, 0x00000023);
pub const CKK_ACTI = @as(c_ulong, 0x00000024);
pub const CKK_CAMELLIA = @as(c_ulong, 0x00000025);
pub const CKK_ARIA = @as(c_ulong, 0x00000026);
pub const CKK_MD5_HMAC = @as(c_ulong, 0x00000027);
pub const CKK_SHA_1_HMAC = @as(c_ulong, 0x00000028);
pub const CKK_RIPEMD128_HMAC = @as(c_ulong, 0x00000029);
pub const CKK_RIPEMD160_HMAC = @as(c_ulong, 0x0000002A);
pub const CKK_SHA256_HMAC = @as(c_ulong, 0x0000002B);
pub const CKK_SHA384_HMAC = @as(c_ulong, 0x0000002C);
pub const CKK_SHA512_HMAC = @as(c_ulong, 0x0000002D);
pub const CKK_SHA224_HMAC = @as(c_ulong, 0x0000002E);
pub const CKK_SEED = @as(c_ulong, 0x0000002F);
pub const CKK_GOSTR3410 = @as(c_ulong, 0x00000030);
pub const CKK_GOSTR3411 = @as(c_ulong, 0x00000031);
pub const CKK_GOST28147 = @as(c_ulong, 0x00000032);
pub const CKK_SHA3_224_HMAC = @as(c_ulong, 0x00000033);
pub const CKK_SHA3_256_HMAC = @as(c_ulong, 0x00000034);
pub const CKK_SHA3_384_HMAC = @as(c_ulong, 0x00000035);
pub const CKK_SHA3_512_HMAC = @as(c_ulong, 0x00000036);
pub const CKK_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CK_CERTIFICATE_CATEGORY_UNSPECIFIED = @as(c_ulong, 0);
pub const CK_CERTIFICATE_CATEGORY_TOKEN_USER = @as(c_ulong, 1);
pub const CK_CERTIFICATE_CATEGORY_AUTHORITY = @as(c_ulong, 2);
pub const CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = @as(c_ulong, 3);
pub const CK_SECURITY_DOMAIN_UNSPECIFIED = @as(c_ulong, 0);
pub const CK_SECURITY_DOMAIN_MANUFACTURER = @as(c_ulong, 1);
pub const CK_SECURITY_DOMAIN_OPERATOR = @as(c_ulong, 2);
pub const CK_SECURITY_DOMAIN_THIRD_PARTY = @as(c_ulong, 3);
pub const CKC_X_509 = @as(c_ulong, 0x00000000);
pub const CKC_X_509_ATTR_CERT = @as(c_ulong, 0x00000001);
pub const CKC_WTLS = @as(c_ulong, 0x00000002);
pub const CKC_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CKF_ARRAY_ATTRIBUTE = @as(c_ulong, 0x40000000);
pub const CK_OTP_FORMAT_DECIMAL = @as(c_ulong, 0);
pub const CK_OTP_FORMAT_HEXADECIMAL = @as(c_ulong, 1);
pub const CK_OTP_FORMAT_ALPHANUMERIC = @as(c_ulong, 2);
pub const CK_OTP_FORMAT_BINARY = @as(c_ulong, 3);
pub const CK_OTP_PARAM_IGNORED = @as(c_ulong, 0);
pub const CK_OTP_PARAM_OPTIONAL = @as(c_ulong, 1);
pub const CK_OTP_PARAM_MANDATORY = @as(c_ulong, 2);
pub const CKA_CLASS = @as(c_ulong, 0x00000000);
pub const CKA_TOKEN = @as(c_ulong, 0x00000001);
pub const CKA_PRIVATE = @as(c_ulong, 0x00000002);
pub const CKA_LABEL = @as(c_ulong, 0x00000003);
pub const CKA_APPLICATION = @as(c_ulong, 0x00000010);
pub const CKA_VALUE = @as(c_ulong, 0x00000011);
pub const CKA_OBJECT_ID = @as(c_ulong, 0x00000012);
pub const CKA_CERTIFICATE_TYPE = @as(c_ulong, 0x00000080);
pub const CKA_ISSUER = @as(c_ulong, 0x00000081);
pub const CKA_SERIAL_NUMBER = @as(c_ulong, 0x00000082);
pub const CKA_AC_ISSUER = @as(c_ulong, 0x00000083);
pub const CKA_OWNER = @as(c_ulong, 0x00000084);
pub const CKA_ATTR_TYPES = @as(c_ulong, 0x00000085);
pub const CKA_TRUSTED = @as(c_ulong, 0x00000086);
pub const CKA_CERTIFICATE_CATEGORY = @as(c_ulong, 0x00000087);
pub const CKA_JAVA_MIDP_SECURITY_DOMAIN = @as(c_ulong, 0x00000088);
pub const CKA_URL = @as(c_ulong, 0x00000089);
pub const CKA_HASH_OF_SUBJECT_PUBLIC_KEY = @as(c_ulong, 0x0000008A);
pub const CKA_HASH_OF_ISSUER_PUBLIC_KEY = @as(c_ulong, 0x0000008B);
pub const CKA_NAME_HASH_ALGORITHM = @as(c_ulong, 0x0000008C);
pub const CKA_CHECK_VALUE = @as(c_ulong, 0x00000090);
pub const CKA_KEY_TYPE = @as(c_ulong, 0x00000100);
pub const CKA_SUBJECT = @as(c_ulong, 0x00000101);
pub const CKA_ID = @as(c_ulong, 0x00000102);
pub const CKA_SENSITIVE = @as(c_ulong, 0x00000103);
pub const CKA_ENCRYPT = @as(c_ulong, 0x00000104);
pub const CKA_DECRYPT = @as(c_ulong, 0x00000105);
pub const CKA_WRAP = @as(c_ulong, 0x00000106);
pub const CKA_UNWRAP = @as(c_ulong, 0x00000107);
pub const CKA_SIGN = @as(c_ulong, 0x00000108);
pub const CKA_SIGN_RECOVER = @as(c_ulong, 0x00000109);
pub const CKA_VERIFY = @as(c_ulong, 0x0000010A);
pub const CKA_VERIFY_RECOVER = @as(c_ulong, 0x0000010B);
pub const CKA_DERIVE = @as(c_ulong, 0x0000010C);
pub const CKA_START_DATE = @as(c_ulong, 0x00000110);
pub const CKA_END_DATE = @as(c_ulong, 0x00000111);
pub const CKA_MODULUS = @as(c_ulong, 0x00000120);
pub const CKA_MODULUS_BITS = @as(c_ulong, 0x00000121);
pub const CKA_PUBLIC_EXPONENT = @as(c_ulong, 0x00000122);
pub const CKA_PRIVATE_EXPONENT = @as(c_ulong, 0x00000123);
pub const CKA_PRIME_1 = @as(c_ulong, 0x00000124);
pub const CKA_PRIME_2 = @as(c_ulong, 0x00000125);
pub const CKA_EXPONENT_1 = @as(c_ulong, 0x00000126);
pub const CKA_EXPONENT_2 = @as(c_ulong, 0x00000127);
pub const CKA_COEFFICIENT = @as(c_ulong, 0x00000128);
pub const CKA_PUBLIC_KEY_INFO = @as(c_ulong, 0x00000129);
pub const CKA_PRIME = @as(c_ulong, 0x00000130);
pub const CKA_SUBPRIME = @as(c_ulong, 0x00000131);
pub const CKA_BASE = @as(c_ulong, 0x00000132);
pub const CKA_PRIME_BITS = @as(c_ulong, 0x00000133);
pub const CKA_SUBPRIME_BITS = @as(c_ulong, 0x00000134);
pub const CKA_SUB_PRIME_BITS = CKA_SUBPRIME_BITS;
pub const CKA_VALUE_BITS = @as(c_ulong, 0x00000160);
pub const CKA_VALUE_LEN = @as(c_ulong, 0x00000161);
pub const CKA_EXTRACTABLE = @as(c_ulong, 0x00000162);
pub const CKA_LOCAL = @as(c_ulong, 0x00000163);
pub const CKA_NEVER_EXTRACTABLE = @as(c_ulong, 0x00000164);
pub const CKA_ALWAYS_SENSITIVE = @as(c_ulong, 0x00000165);
pub const CKA_KEY_GEN_MECHANISM = @as(c_ulong, 0x00000166);
pub const CKA_MODIFIABLE = @as(c_ulong, 0x00000170);
pub const CKA_COPYABLE = @as(c_ulong, 0x00000171);
pub const CKA_DESTROYABLE = @as(c_ulong, 0x00000172);
pub const CKA_ECDSA_PARAMS = @as(c_ulong, 0x00000180);
pub const CKA_EC_PARAMS = @as(c_ulong, 0x00000180);
pub const CKA_EC_POINT = @as(c_ulong, 0x00000181);
pub const CKA_SECONDARY_AUTH = @as(c_ulong, 0x00000200);
pub const CKA_AUTH_PIN_FLAGS = @as(c_ulong, 0x00000201);
pub const CKA_ALWAYS_AUTHENTICATE = @as(c_ulong, 0x00000202);
pub const CKA_WRAP_WITH_TRUSTED = @as(c_ulong, 0x00000210);
pub const CKA_WRAP_TEMPLATE = CKF_ARRAY_ATTRIBUTE | @as(c_ulong, 0x00000211);
pub const CKA_UNWRAP_TEMPLATE = CKF_ARRAY_ATTRIBUTE | @as(c_ulong, 0x00000212);
pub const CKA_DERIVE_TEMPLATE = CKF_ARRAY_ATTRIBUTE | @as(c_ulong, 0x00000213);
pub const CKA_OTP_FORMAT = @as(c_ulong, 0x00000220);
pub const CKA_OTP_LENGTH = @as(c_ulong, 0x00000221);
pub const CKA_OTP_TIME_INTERVAL = @as(c_ulong, 0x00000222);
pub const CKA_OTP_USER_FRIENDLY_MODE = @as(c_ulong, 0x00000223);
pub const CKA_OTP_CHALLENGE_REQUIREMENT = @as(c_ulong, 0x00000224);
pub const CKA_OTP_TIME_REQUIREMENT = @as(c_ulong, 0x00000225);
pub const CKA_OTP_COUNTER_REQUIREMENT = @as(c_ulong, 0x00000226);
pub const CKA_OTP_PIN_REQUIREMENT = @as(c_ulong, 0x00000227);
pub const CKA_OTP_COUNTER = @as(c_ulong, 0x0000022E);
pub const CKA_OTP_TIME = @as(c_ulong, 0x0000022F);
pub const CKA_OTP_USER_IDENTIFIER = @as(c_ulong, 0x0000022A);
pub const CKA_OTP_SERVICE_IDENTIFIER = @as(c_ulong, 0x0000022B);
pub const CKA_OTP_SERVICE_LOGO = @as(c_ulong, 0x0000022C);
pub const CKA_OTP_SERVICE_LOGO_TYPE = @as(c_ulong, 0x0000022D);
pub const CKA_GOSTR3410_PARAMS = @as(c_ulong, 0x00000250);
pub const CKA_GOSTR3411_PARAMS = @as(c_ulong, 0x00000251);
pub const CKA_GOST28147_PARAMS = @as(c_ulong, 0x00000252);
pub const CKA_HW_FEATURE_TYPE = @as(c_ulong, 0x00000300);
pub const CKA_RESET_ON_INIT = @as(c_ulong, 0x00000301);
pub const CKA_HAS_RESET = @as(c_ulong, 0x00000302);
pub const CKA_PIXEL_X = @as(c_ulong, 0x00000400);
pub const CKA_PIXEL_Y = @as(c_ulong, 0x00000401);
pub const CKA_RESOLUTION = @as(c_ulong, 0x00000402);
pub const CKA_CHAR_ROWS = @as(c_ulong, 0x00000403);
pub const CKA_CHAR_COLUMNS = @as(c_ulong, 0x00000404);
pub const CKA_COLOR = @as(c_ulong, 0x00000405);
pub const CKA_BITS_PER_PIXEL = @as(c_ulong, 0x00000406);
pub const CKA_CHAR_SETS = @as(c_ulong, 0x00000480);
pub const CKA_ENCODING_METHODS = @as(c_ulong, 0x00000481);
pub const CKA_MIME_TYPES = @as(c_ulong, 0x00000482);
pub const CKA_MECHANISM_TYPE = @as(c_ulong, 0x00000500);
pub const CKA_REQUIRED_CMS_ATTRIBUTES = @as(c_ulong, 0x00000501);
pub const CKA_DEFAULT_CMS_ATTRIBUTES = @as(c_ulong, 0x00000502);
pub const CKA_SUPPORTED_CMS_ATTRIBUTES = @as(c_ulong, 0x00000503);
pub const CKA_ALLOWED_MECHANISMS = CKF_ARRAY_ATTRIBUTE | @as(c_ulong, 0x00000600);
pub const CKA_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CKM_RSA_PKCS_KEY_PAIR_GEN = @as(c_ulong, 0x00000000);
pub const CKM_RSA_PKCS = @as(c_ulong, 0x00000001);
pub const CKM_RSA_9796 = @as(c_ulong, 0x00000002);
pub const CKM_RSA_X_509 = @as(c_ulong, 0x00000003);
pub const CKM_MD2_RSA_PKCS = @as(c_ulong, 0x00000004);
pub const CKM_MD5_RSA_PKCS = @as(c_ulong, 0x00000005);
pub const CKM_SHA1_RSA_PKCS = @as(c_ulong, 0x00000006);
pub const CKM_RIPEMD128_RSA_PKCS = @as(c_ulong, 0x00000007);
pub const CKM_RIPEMD160_RSA_PKCS = @as(c_ulong, 0x00000008);
pub const CKM_RSA_PKCS_OAEP = @as(c_ulong, 0x00000009);
pub const CKM_RSA_X9_31_KEY_PAIR_GEN = @as(c_ulong, 0x0000000A);
pub const CKM_RSA_X9_31 = @as(c_ulong, 0x0000000B);
pub const CKM_SHA1_RSA_X9_31 = @as(c_ulong, 0x0000000C);
pub const CKM_RSA_PKCS_PSS = @as(c_ulong, 0x0000000D);
pub const CKM_SHA1_RSA_PKCS_PSS = @as(c_ulong, 0x0000000E);
pub const CKM_DSA_KEY_PAIR_GEN = @as(c_ulong, 0x00000010);
pub const CKM_DSA = @as(c_ulong, 0x00000011);
pub const CKM_DSA_SHA1 = @as(c_ulong, 0x00000012);
pub const CKM_DSA_SHA224 = @as(c_ulong, 0x00000013);
pub const CKM_DSA_SHA256 = @as(c_ulong, 0x00000014);
pub const CKM_DSA_SHA384 = @as(c_ulong, 0x00000015);
pub const CKM_DSA_SHA512 = @as(c_ulong, 0x00000016);
pub const CKM_DSA_SHA3_224 = @as(c_ulong, 0x00000018);
pub const CKM_DSA_SHA3_256 = @as(c_ulong, 0x00000019);
pub const CKM_DSA_SHA3_384 = @as(c_ulong, 0x0000001A);
pub const CKM_DSA_SHA3_512 = @as(c_ulong, 0x0000001B);
pub const CKM_DH_PKCS_KEY_PAIR_GEN = @as(c_ulong, 0x00000020);
pub const CKM_DH_PKCS_DERIVE = @as(c_ulong, 0x00000021);
pub const CKM_X9_42_DH_KEY_PAIR_GEN = @as(c_ulong, 0x00000030);
pub const CKM_X9_42_DH_DERIVE = @as(c_ulong, 0x00000031);
pub const CKM_X9_42_DH_HYBRID_DERIVE = @as(c_ulong, 0x00000032);
pub const CKM_X9_42_MQV_DERIVE = @as(c_ulong, 0x00000033);
pub const CKM_SHA256_RSA_PKCS = @as(c_ulong, 0x00000040);
pub const CKM_SHA384_RSA_PKCS = @as(c_ulong, 0x00000041);
pub const CKM_SHA512_RSA_PKCS = @as(c_ulong, 0x00000042);
pub const CKM_SHA256_RSA_PKCS_PSS = @as(c_ulong, 0x00000043);
pub const CKM_SHA384_RSA_PKCS_PSS = @as(c_ulong, 0x00000044);
pub const CKM_SHA512_RSA_PKCS_PSS = @as(c_ulong, 0x00000045);
pub const CKM_SHA224_RSA_PKCS = @as(c_ulong, 0x00000046);
pub const CKM_SHA224_RSA_PKCS_PSS = @as(c_ulong, 0x00000047);
pub const CKM_SHA512_224 = @as(c_ulong, 0x00000048);
pub const CKM_SHA512_224_HMAC = @as(c_ulong, 0x00000049);
pub const CKM_SHA512_224_HMAC_GENERAL = @as(c_ulong, 0x0000004A);
pub const CKM_SHA512_224_KEY_DERIVATION = @as(c_ulong, 0x0000004B);
pub const CKM_SHA512_256 = @as(c_ulong, 0x0000004C);
pub const CKM_SHA512_256_HMAC = @as(c_ulong, 0x0000004D);
pub const CKM_SHA512_256_HMAC_GENERAL = @as(c_ulong, 0x0000004E);
pub const CKM_SHA512_256_KEY_DERIVATION = @as(c_ulong, 0x0000004F);
pub const CKM_SHA512_T = @as(c_ulong, 0x00000050);
pub const CKM_SHA512_T_HMAC = @as(c_ulong, 0x00000051);
pub const CKM_SHA512_T_HMAC_GENERAL = @as(c_ulong, 0x00000052);
pub const CKM_SHA512_T_KEY_DERIVATION = @as(c_ulong, 0x00000053);
pub const CKM_SHA3_256_RSA_PKCS = @as(c_ulong, 0x00000060);
pub const CKM_SHA3_384_RSA_PKCS = @as(c_ulong, 0x00000061);
pub const CKM_SHA3_512_RSA_PKCS = @as(c_ulong, 0x00000062);
pub const CKM_SHA3_256_RSA_PKCS_PSS = @as(c_ulong, 0x00000063);
pub const CKM_SHA3_384_RSA_PKCS_PSS = @as(c_ulong, 0x00000064);
pub const CKM_SHA3_512_RSA_PKCS_PSS = @as(c_ulong, 0x00000065);
pub const CKM_SHA3_224_RSA_PKCS = @as(c_ulong, 0x00000066);
pub const CKM_SHA3_224_RSA_PKCS_PSS = @as(c_ulong, 0x00000067);
pub const CKM_RC2_KEY_GEN = @as(c_ulong, 0x00000100);
pub const CKM_RC2_ECB = @as(c_ulong, 0x00000101);
pub const CKM_RC2_CBC = @as(c_ulong, 0x00000102);
pub const CKM_RC2_MAC = @as(c_ulong, 0x00000103);
pub const CKM_RC2_MAC_GENERAL = @as(c_ulong, 0x00000104);
pub const CKM_RC2_CBC_PAD = @as(c_ulong, 0x00000105);
pub const CKM_RC4_KEY_GEN = @as(c_ulong, 0x00000110);
pub const CKM_RC4 = @as(c_ulong, 0x00000111);
pub const CKM_DES_KEY_GEN = @as(c_ulong, 0x00000120);
pub const CKM_DES_ECB = @as(c_ulong, 0x00000121);
pub const CKM_DES_CBC = @as(c_ulong, 0x00000122);
pub const CKM_DES_MAC = @as(c_ulong, 0x00000123);
pub const CKM_DES_MAC_GENERAL = @as(c_ulong, 0x00000124);
pub const CKM_DES_CBC_PAD = @as(c_ulong, 0x00000125);
pub const CKM_DES2_KEY_GEN = @as(c_ulong, 0x00000130);
pub const CKM_DES3_KEY_GEN = @as(c_ulong, 0x00000131);
pub const CKM_DES3_ECB = @as(c_ulong, 0x00000132);
pub const CKM_DES3_CBC = @as(c_ulong, 0x00000133);
pub const CKM_DES3_MAC = @as(c_ulong, 0x00000134);
pub const CKM_DES3_MAC_GENERAL = @as(c_ulong, 0x00000135);
pub const CKM_DES3_CBC_PAD = @as(c_ulong, 0x00000136);
pub const CKM_DES3_CMAC_GENERAL = @as(c_ulong, 0x00000137);
pub const CKM_DES3_CMAC = @as(c_ulong, 0x00000138);
pub const CKM_CDMF_KEY_GEN = @as(c_ulong, 0x00000140);
pub const CKM_CDMF_ECB = @as(c_ulong, 0x00000141);
pub const CKM_CDMF_CBC = @as(c_ulong, 0x00000142);
pub const CKM_CDMF_MAC = @as(c_ulong, 0x00000143);
pub const CKM_CDMF_MAC_GENERAL = @as(c_ulong, 0x00000144);
pub const CKM_CDMF_CBC_PAD = @as(c_ulong, 0x00000145);
pub const CKM_DES_OFB64 = @as(c_ulong, 0x00000150);
pub const CKM_DES_OFB8 = @as(c_ulong, 0x00000151);
pub const CKM_DES_CFB64 = @as(c_ulong, 0x00000152);
pub const CKM_DES_CFB8 = @as(c_ulong, 0x00000153);
pub const CKM_MD2 = @as(c_ulong, 0x00000200);
pub const CKM_MD2_HMAC = @as(c_ulong, 0x00000201);
pub const CKM_MD2_HMAC_GENERAL = @as(c_ulong, 0x00000202);
pub const CKM_MD5 = @as(c_ulong, 0x00000210);
pub const CKM_MD5_HMAC = @as(c_ulong, 0x00000211);
pub const CKM_MD5_HMAC_GENERAL = @as(c_ulong, 0x00000212);
pub const CKM_SHA_1 = @as(c_ulong, 0x00000220);
pub const CKM_SHA_1_HMAC = @as(c_ulong, 0x00000221);
pub const CKM_SHA_1_HMAC_GENERAL = @as(c_ulong, 0x00000222);
pub const CKM_RIPEMD128 = @as(c_ulong, 0x00000230);
pub const CKM_RIPEMD128_HMAC = @as(c_ulong, 0x00000231);
pub const CKM_RIPEMD128_HMAC_GENERAL = @as(c_ulong, 0x00000232);
pub const CKM_RIPEMD160 = @as(c_ulong, 0x00000240);
pub const CKM_RIPEMD160_HMAC = @as(c_ulong, 0x00000241);
pub const CKM_RIPEMD160_HMAC_GENERAL = @as(c_ulong, 0x00000242);
pub const CKM_SHA256 = @as(c_ulong, 0x00000250);
pub const CKM_SHA256_HMAC = @as(c_ulong, 0x00000251);
pub const CKM_SHA256_HMAC_GENERAL = @as(c_ulong, 0x00000252);
pub const CKM_SHA224 = @as(c_ulong, 0x00000255);
pub const CKM_SHA224_HMAC = @as(c_ulong, 0x00000256);
pub const CKM_SHA224_HMAC_GENERAL = @as(c_ulong, 0x00000257);
pub const CKM_SHA384 = @as(c_ulong, 0x00000260);
pub const CKM_SHA384_HMAC = @as(c_ulong, 0x00000261);
pub const CKM_SHA384_HMAC_GENERAL = @as(c_ulong, 0x00000262);
pub const CKM_SHA512 = @as(c_ulong, 0x00000270);
pub const CKM_SHA512_HMAC = @as(c_ulong, 0x00000271);
pub const CKM_SHA512_HMAC_GENERAL = @as(c_ulong, 0x00000272);
pub const CKM_SECURID_KEY_GEN = @as(c_ulong, 0x00000280);
pub const CKM_SECURID = @as(c_ulong, 0x00000282);
pub const CKM_HOTP_KEY_GEN = @as(c_ulong, 0x00000290);
pub const CKM_HOTP = @as(c_ulong, 0x00000291);
pub const CKM_ACTI = @as(c_ulong, 0x000002A0);
pub const CKM_ACTI_KEY_GEN = @as(c_ulong, 0x000002A1);
pub const CKM_SHA3_256 = @as(c_ulong, 0x000002B0);
pub const CKM_SHA3_256_HMAC = @as(c_ulong, 0x000002B1);
pub const CKM_SHA3_256_HMAC_GENERAL = @as(c_ulong, 0x000002B2);
pub const CKM_SHA3_256_KEY_GEN = @as(c_ulong, 0x000002B3);
pub const CKM_SHA3_224 = @as(c_ulong, 0x000002B5);
pub const CKM_SHA3_224_HMAC = @as(c_ulong, 0x000002B6);
pub const CKM_SHA3_224_HMAC_GENERAL = @as(c_ulong, 0x000002B7);
pub const CKM_SHA3_224_KEY_GEN = @as(c_ulong, 0x000002B8);
pub const CKM_SHA3_384 = @as(c_ulong, 0x000002C0);
pub const CKM_SHA3_384_HMAC = @as(c_ulong, 0x000002C1);
pub const CKM_SHA3_384_HMAC_GENERAL = @as(c_ulong, 0x000002C2);
pub const CKM_SHA3_384_KEY_GEN = @as(c_ulong, 0x000002C3);
pub const CKM_SHA3_512 = @as(c_ulong, 0x000002D0);
pub const CKM_SHA3_512_HMAC = @as(c_ulong, 0x000002D1);
pub const CKM_SHA3_512_HMAC_GENERAL = @as(c_ulong, 0x000002D2);
pub const CKM_SHA3_512_KEY_GEN = @as(c_ulong, 0x000002D3);
pub const CKM_CAST_KEY_GEN = @as(c_ulong, 0x00000300);
pub const CKM_CAST_ECB = @as(c_ulong, 0x00000301);
pub const CKM_CAST_CBC = @as(c_ulong, 0x00000302);
pub const CKM_CAST_MAC = @as(c_ulong, 0x00000303);
pub const CKM_CAST_MAC_GENERAL = @as(c_ulong, 0x00000304);
pub const CKM_CAST_CBC_PAD = @as(c_ulong, 0x00000305);
pub const CKM_CAST3_KEY_GEN = @as(c_ulong, 0x00000310);
pub const CKM_CAST3_ECB = @as(c_ulong, 0x00000311);
pub const CKM_CAST3_CBC = @as(c_ulong, 0x00000312);
pub const CKM_CAST3_MAC = @as(c_ulong, 0x00000313);
pub const CKM_CAST3_MAC_GENERAL = @as(c_ulong, 0x00000314);
pub const CKM_CAST3_CBC_PAD = @as(c_ulong, 0x00000315);
pub const CKM_CAST5_KEY_GEN = @as(c_ulong, 0x00000320);
pub const CKM_CAST128_KEY_GEN = @as(c_ulong, 0x00000320);
pub const CKM_CAST5_ECB = @as(c_ulong, 0x00000321);
pub const CKM_CAST128_ECB = @as(c_ulong, 0x00000321);
pub const CKM_CAST5_CBC = @as(c_ulong, 0x00000322);
pub const CKM_CAST128_CBC = @as(c_ulong, 0x00000322);
pub const CKM_CAST5_MAC = @as(c_ulong, 0x00000323);
pub const CKM_CAST128_MAC = @as(c_ulong, 0x00000323);
pub const CKM_CAST5_MAC_GENERAL = @as(c_ulong, 0x00000324);
pub const CKM_CAST128_MAC_GENERAL = @as(c_ulong, 0x00000324);
pub const CKM_CAST5_CBC_PAD = @as(c_ulong, 0x00000325);
pub const CKM_CAST128_CBC_PAD = @as(c_ulong, 0x00000325);
pub const CKM_RC5_KEY_GEN = @as(c_ulong, 0x00000330);
pub const CKM_RC5_ECB = @as(c_ulong, 0x00000331);
pub const CKM_RC5_CBC = @as(c_ulong, 0x00000332);
pub const CKM_RC5_MAC = @as(c_ulong, 0x00000333);
pub const CKM_RC5_MAC_GENERAL = @as(c_ulong, 0x00000334);
pub const CKM_RC5_CBC_PAD = @as(c_ulong, 0x00000335);
pub const CKM_IDEA_KEY_GEN = @as(c_ulong, 0x00000340);
pub const CKM_IDEA_ECB = @as(c_ulong, 0x00000341);
pub const CKM_IDEA_CBC = @as(c_ulong, 0x00000342);
pub const CKM_IDEA_MAC = @as(c_ulong, 0x00000343);
pub const CKM_IDEA_MAC_GENERAL = @as(c_ulong, 0x00000344);
pub const CKM_IDEA_CBC_PAD = @as(c_ulong, 0x00000345);
pub const CKM_GENERIC_SECRET_KEY_GEN = @as(c_ulong, 0x00000350);
pub const CKM_CONCATENATE_BASE_AND_KEY = @as(c_ulong, 0x00000360);
pub const CKM_CONCATENATE_BASE_AND_DATA = @as(c_ulong, 0x00000362);
pub const CKM_CONCATENATE_DATA_AND_BASE = @as(c_ulong, 0x00000363);
pub const CKM_XOR_BASE_AND_DATA = @as(c_ulong, 0x00000364);
pub const CKM_EXTRACT_KEY_FROM_KEY = @as(c_ulong, 0x00000365);
pub const CKM_SSL3_PRE_MASTER_KEY_GEN = @as(c_ulong, 0x00000370);
pub const CKM_SSL3_MASTER_KEY_DERIVE = @as(c_ulong, 0x00000371);
pub const CKM_SSL3_KEY_AND_MAC_DERIVE = @as(c_ulong, 0x00000372);
pub const CKM_SSL3_MASTER_KEY_DERIVE_DH = @as(c_ulong, 0x00000373);
pub const CKM_TLS_PRE_MASTER_KEY_GEN = @as(c_ulong, 0x00000374);
pub const CKM_TLS_MASTER_KEY_DERIVE = @as(c_ulong, 0x00000375);
pub const CKM_TLS_KEY_AND_MAC_DERIVE = @as(c_ulong, 0x00000376);
pub const CKM_TLS_MASTER_KEY_DERIVE_DH = @as(c_ulong, 0x00000377);
pub const CKM_TLS_PRF = @as(c_ulong, 0x00000378);
pub const CKM_SSL3_MD5_MAC = @as(c_ulong, 0x00000380);
pub const CKM_SSL3_SHA1_MAC = @as(c_ulong, 0x00000381);
pub const CKM_MD5_KEY_DERIVATION = @as(c_ulong, 0x00000390);
pub const CKM_MD2_KEY_DERIVATION = @as(c_ulong, 0x00000391);
pub const CKM_SHA1_KEY_DERIVATION = @as(c_ulong, 0x00000392);
pub const CKM_SHA256_KEY_DERIVATION = @as(c_ulong, 0x00000393);
pub const CKM_SHA384_KEY_DERIVATION = @as(c_ulong, 0x00000394);
pub const CKM_SHA512_KEY_DERIVATION = @as(c_ulong, 0x00000395);
pub const CKM_SHA224_KEY_DERIVATION = @as(c_ulong, 0x00000396);
pub const CKM_SHA3_256_KEY_DERIVE = @as(c_ulong, 0x00000397);
pub const CKM_SHA3_224_KEY_DERIVE = @as(c_ulong, 0x00000398);
pub const CKM_SHA3_384_KEY_DERIVE = @as(c_ulong, 0x00000399);
pub const CKM_SHA3_512_KEY_DERIVE = @as(c_ulong, 0x0000039A);
pub const CKM_SHAKE_128_KEY_DERIVE = @as(c_ulong, 0x0000039B);
pub const CKM_SHAKE_256_KEY_DERIVE = @as(c_ulong, 0x0000039C);
pub const CKM_PBE_MD2_DES_CBC = @as(c_ulong, 0x000003A0);
pub const CKM_PBE_MD5_DES_CBC = @as(c_ulong, 0x000003A1);
pub const CKM_PBE_MD5_CAST_CBC = @as(c_ulong, 0x000003A2);
pub const CKM_PBE_MD5_CAST3_CBC = @as(c_ulong, 0x000003A3);
pub const CKM_PBE_MD5_CAST5_CBC = @as(c_ulong, 0x000003A4);
pub const CKM_PBE_MD5_CAST128_CBC = @as(c_ulong, 0x000003A4);
pub const CKM_PBE_SHA1_CAST5_CBC = @as(c_ulong, 0x000003A5);
pub const CKM_PBE_SHA1_CAST128_CBC = @as(c_ulong, 0x000003A5);
pub const CKM_PBE_SHA1_RC4_128 = @as(c_ulong, 0x000003A6);
pub const CKM_PBE_SHA1_RC4_40 = @as(c_ulong, 0x000003A7);
pub const CKM_PBE_SHA1_DES3_EDE_CBC = @as(c_ulong, 0x000003A8);
pub const CKM_PBE_SHA1_DES2_EDE_CBC = @as(c_ulong, 0x000003A9);
pub const CKM_PBE_SHA1_RC2_128_CBC = @as(c_ulong, 0x000003AA);
pub const CKM_PBE_SHA1_RC2_40_CBC = @as(c_ulong, 0x000003AB);
pub const CKM_PKCS5_PBKD2 = @as(c_ulong, 0x000003B0);
pub const CKM_PBA_SHA1_WITH_SHA1_HMAC = @as(c_ulong, 0x000003C0);
pub const CKM_WTLS_PRE_MASTER_KEY_GEN = @as(c_ulong, 0x000003D0);
pub const CKM_WTLS_MASTER_KEY_DERIVE = @as(c_ulong, 0x000003D1);
pub const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = @as(c_ulong, 0x000003D2);
pub const CKM_WTLS_PRF = @as(c_ulong, 0x000003D3);
pub const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = @as(c_ulong, 0x000003D4);
pub const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = @as(c_ulong, 0x000003D5);
pub const CKM_TLS10_MAC_SERVER = @as(c_ulong, 0x000003D6);
pub const CKM_TLS10_MAC_CLIENT = @as(c_ulong, 0x000003D7);
pub const CKM_TLS12_MAC = @as(c_ulong, 0x000003D8);
pub const CKM_TLS12_KDF = @as(c_ulong, 0x000003D9);
pub const CKM_TLS12_MASTER_KEY_DERIVE = @as(c_ulong, 0x000003E0);
pub const CKM_TLS12_KEY_AND_MAC_DERIVE = @as(c_ulong, 0x000003E1);
pub const CKM_TLS12_MASTER_KEY_DERIVE_DH = @as(c_ulong, 0x000003E2);
pub const CKM_TLS12_KEY_SAFE_DERIVE = @as(c_ulong, 0x000003E3);
pub const CKM_TLS_MAC = @as(c_ulong, 0x000003E4);
pub const CKM_TLS_KDF = @as(c_ulong, 0x000003E5);
pub const CKM_KEY_WRAP_LYNKS = @as(c_ulong, 0x00000400);
pub const CKM_KEY_WRAP_SET_OAEP = @as(c_ulong, 0x00000401);
pub const CKM_CMS_SIG = @as(c_ulong, 0x00000500);
pub const CKM_KIP_DERIVE = @as(c_ulong, 0x00000510);
pub const CKM_KIP_WRAP = @as(c_ulong, 0x00000511);
pub const CKM_KIP_MAC = @as(c_ulong, 0x00000512);
pub const CKM_CAMELLIA_KEY_GEN = @as(c_ulong, 0x00000550);
pub const CKM_CAMELLIA_ECB = @as(c_ulong, 0x00000551);
pub const CKM_CAMELLIA_CBC = @as(c_ulong, 0x00000552);
pub const CKM_CAMELLIA_MAC = @as(c_ulong, 0x00000553);
pub const CKM_CAMELLIA_MAC_GENERAL = @as(c_ulong, 0x00000554);
pub const CKM_CAMELLIA_CBC_PAD = @as(c_ulong, 0x00000555);
pub const CKM_CAMELLIA_ECB_ENCRYPT_DATA = @as(c_ulong, 0x00000556);
pub const CKM_CAMELLIA_CBC_ENCRYPT_DATA = @as(c_ulong, 0x00000557);
pub const CKM_CAMELLIA_CTR = @as(c_ulong, 0x00000558);
pub const CKM_ARIA_KEY_GEN = @as(c_ulong, 0x00000560);
pub const CKM_ARIA_ECB = @as(c_ulong, 0x00000561);
pub const CKM_ARIA_CBC = @as(c_ulong, 0x00000562);
pub const CKM_ARIA_MAC = @as(c_ulong, 0x00000563);
pub const CKM_ARIA_MAC_GENERAL = @as(c_ulong, 0x00000564);
pub const CKM_ARIA_CBC_PAD = @as(c_ulong, 0x00000565);
pub const CKM_ARIA_ECB_ENCRYPT_DATA = @as(c_ulong, 0x00000566);
pub const CKM_ARIA_CBC_ENCRYPT_DATA = @as(c_ulong, 0x00000567);
pub const CKM_SEED_KEY_GEN = @as(c_ulong, 0x00000650);
pub const CKM_SEED_ECB = @as(c_ulong, 0x00000651);
pub const CKM_SEED_CBC = @as(c_ulong, 0x00000652);
pub const CKM_SEED_MAC = @as(c_ulong, 0x00000653);
pub const CKM_SEED_MAC_GENERAL = @as(c_ulong, 0x00000654);
pub const CKM_SEED_CBC_PAD = @as(c_ulong, 0x00000655);
pub const CKM_SEED_ECB_ENCRYPT_DATA = @as(c_ulong, 0x00000656);
pub const CKM_SEED_CBC_ENCRYPT_DATA = @as(c_ulong, 0x00000657);
pub const CKM_SKIPJACK_KEY_GEN = @as(c_ulong, 0x00001000);
pub const CKM_SKIPJACK_ECB64 = @as(c_ulong, 0x00001001);
pub const CKM_SKIPJACK_CBC64 = @as(c_ulong, 0x00001002);
pub const CKM_SKIPJACK_OFB64 = @as(c_ulong, 0x00001003);
pub const CKM_SKIPJACK_CFB64 = @as(c_ulong, 0x00001004);
pub const CKM_SKIPJACK_CFB32 = @as(c_ulong, 0x00001005);
pub const CKM_SKIPJACK_CFB16 = @as(c_ulong, 0x00001006);
pub const CKM_SKIPJACK_CFB8 = @as(c_ulong, 0x00001007);
pub const CKM_SKIPJACK_WRAP = @as(c_ulong, 0x00001008);
pub const CKM_SKIPJACK_PRIVATE_WRAP = @as(c_ulong, 0x00001009);
pub const CKM_SKIPJACK_RELAYX = @as(c_ulong, 0x0000100a);
pub const CKM_KEA_KEY_PAIR_GEN = @as(c_ulong, 0x00001010);
pub const CKM_KEA_KEY_DERIVE = @as(c_ulong, 0x00001011);
pub const CKM_KEA_DERIVE = @as(c_ulong, 0x00001012);
pub const CKM_FORTEZZA_TIMESTAMP = @as(c_ulong, 0x00001020);
pub const CKM_BATON_KEY_GEN = @as(c_ulong, 0x00001030);
pub const CKM_BATON_ECB128 = @as(c_ulong, 0x00001031);
pub const CKM_BATON_ECB96 = @as(c_ulong, 0x00001032);
pub const CKM_BATON_CBC128 = @as(c_ulong, 0x00001033);
pub const CKM_BATON_COUNTER = @as(c_ulong, 0x00001034);
pub const CKM_BATON_SHUFFLE = @as(c_ulong, 0x00001035);
pub const CKM_BATON_WRAP = @as(c_ulong, 0x00001036);
pub const CKM_ECDSA_KEY_PAIR_GEN = @as(c_ulong, 0x00001040);
pub const CKM_EC_KEY_PAIR_GEN = @as(c_ulong, 0x00001040);
pub const CKM_ECDSA = @as(c_ulong, 0x00001041);
pub const CKM_ECDSA_SHA1 = @as(c_ulong, 0x00001042);
pub const CKM_ECDSA_SHA224 = @as(c_ulong, 0x00001043);
pub const CKM_ECDSA_SHA256 = @as(c_ulong, 0x00001044);
pub const CKM_ECDSA_SHA384 = @as(c_ulong, 0x00001045);
pub const CKM_ECDSA_SHA512 = @as(c_ulong, 0x00001046);
pub const CKM_ECDH1_DERIVE = @as(c_ulong, 0x00001050);
pub const CKM_ECDH1_COFACTOR_DERIVE = @as(c_ulong, 0x00001051);
pub const CKM_ECMQV_DERIVE = @as(c_ulong, 0x00001052);
pub const CKM_ECDH_AES_KEY_WRAP = @as(c_ulong, 0x00001053);
pub const CKM_RSA_AES_KEY_WRAP = @as(c_ulong, 0x00001054);
pub const CKM_JUNIPER_KEY_GEN = @as(c_ulong, 0x00001060);
pub const CKM_JUNIPER_ECB128 = @as(c_ulong, 0x00001061);
pub const CKM_JUNIPER_CBC128 = @as(c_ulong, 0x00001062);
pub const CKM_JUNIPER_COUNTER = @as(c_ulong, 0x00001063);
pub const CKM_JUNIPER_SHUFFLE = @as(c_ulong, 0x00001064);
pub const CKM_JUNIPER_WRAP = @as(c_ulong, 0x00001065);
pub const CKM_FASTHASH = @as(c_ulong, 0x00001070);
pub const CKM_AES_KEY_GEN = @as(c_ulong, 0x00001080);
pub const CKM_AES_ECB = @as(c_ulong, 0x00001081);
pub const CKM_AES_CBC = @as(c_ulong, 0x00001082);
pub const CKM_AES_MAC = @as(c_ulong, 0x00001083);
pub const CKM_AES_MAC_GENERAL = @as(c_ulong, 0x00001084);
pub const CKM_AES_CBC_PAD = @as(c_ulong, 0x00001085);
pub const CKM_AES_CTR = @as(c_ulong, 0x00001086);
pub const CKM_AES_GCM = @as(c_ulong, 0x00001087);
pub const CKM_AES_CCM = @as(c_ulong, 0x00001088);
pub const CKM_AES_CTS = @as(c_ulong, 0x00001089);
pub const CKM_AES_CMAC = @as(c_ulong, 0x0000108A);
pub const CKM_AES_CMAC_GENERAL = @as(c_ulong, 0x0000108B);
pub const CKM_AES_XCBC_MAC = @as(c_ulong, 0x0000108C);
pub const CKM_AES_XCBC_MAC_96 = @as(c_ulong, 0x0000108D);
pub const CKM_AES_GMAC = @as(c_ulong, 0x0000108E);
pub const CKM_BLOWFISH_KEY_GEN = @as(c_ulong, 0x00001090);
pub const CKM_BLOWFISH_CBC = @as(c_ulong, 0x00001091);
pub const CKM_TWOFISH_KEY_GEN = @as(c_ulong, 0x00001092);
pub const CKM_TWOFISH_CBC = @as(c_ulong, 0x00001093);
pub const CKM_BLOWFISH_CBC_PAD = @as(c_ulong, 0x00001094);
pub const CKM_TWOFISH_CBC_PAD = @as(c_ulong, 0x00001095);
pub const CKM_DES_ECB_ENCRYPT_DATA = @as(c_ulong, 0x00001100);
pub const CKM_DES_CBC_ENCRYPT_DATA = @as(c_ulong, 0x00001101);
pub const CKM_DES3_ECB_ENCRYPT_DATA = @as(c_ulong, 0x00001102);
pub const CKM_DES3_CBC_ENCRYPT_DATA = @as(c_ulong, 0x00001103);
pub const CKM_AES_ECB_ENCRYPT_DATA = @as(c_ulong, 0x00001104);
pub const CKM_AES_CBC_ENCRYPT_DATA = @as(c_ulong, 0x00001105);
pub const CKM_GOSTR3410_KEY_PAIR_GEN = @as(c_ulong, 0x00001200);
pub const CKM_GOSTR3410 = @as(c_ulong, 0x00001201);
pub const CKM_GOSTR3410_WITH_GOSTR3411 = @as(c_ulong, 0x00001202);
pub const CKM_GOSTR3410_KEY_WRAP = @as(c_ulong, 0x00001203);
pub const CKM_GOSTR3410_DERIVE = @as(c_ulong, 0x00001204);
pub const CKM_GOSTR3411 = @as(c_ulong, 0x00001210);
pub const CKM_GOSTR3411_HMAC = @as(c_ulong, 0x00001211);
pub const CKM_GOST28147_KEY_GEN = @as(c_ulong, 0x00001220);
pub const CKM_GOST28147_ECB = @as(c_ulong, 0x00001221);
pub const CKM_GOST28147 = @as(c_ulong, 0x00001222);
pub const CKM_GOST28147_MAC = @as(c_ulong, 0x00001223);
pub const CKM_GOST28147_KEY_WRAP = @as(c_ulong, 0x00001224);
pub const CKM_DSA_PARAMETER_GEN = @as(c_ulong, 0x00002000);
pub const CKM_DH_PKCS_PARAMETER_GEN = @as(c_ulong, 0x00002001);
pub const CKM_X9_42_DH_PARAMETER_GEN = @as(c_ulong, 0x00002002);
pub const CKM_DSA_PROBABLISTIC_PARAMETER_GEN = @as(c_ulong, 0x00002003);
pub const CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN = @as(c_ulong, 0x00002004);
pub const CKM_AES_OFB = @as(c_ulong, 0x00002104);
pub const CKM_AES_CFB64 = @as(c_ulong, 0x00002105);
pub const CKM_AES_CFB8 = @as(c_ulong, 0x00002106);
pub const CKM_AES_CFB128 = @as(c_ulong, 0x00002107);
pub const CKM_AES_CFB1 = @as(c_ulong, 0x00002108);
pub const CKM_AES_KEY_WRAP = @as(c_ulong, 0x00002109);
pub const CKM_AES_KEY_WRAP_PAD = @as(c_ulong, 0x0000210A);
pub const CKM_RSA_PKCS_TPM_1_1 = @as(c_ulong, 0x00004001);
pub const CKM_RSA_PKCS_OAEP_TPM_1_1 = @as(c_ulong, 0x00004002);
pub const CKM_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CKF_HW = @as(c_ulong, 0x00000001);
pub const CKF_ENCRYPT = @as(c_ulong, 0x00000100);
pub const CKF_DECRYPT = @as(c_ulong, 0x00000200);
pub const CKF_DIGEST = @as(c_ulong, 0x00000400);
pub const CKF_SIGN = @as(c_ulong, 0x00000800);
pub const CKF_SIGN_RECOVER = @as(c_ulong, 0x00001000);
pub const CKF_VERIFY = @as(c_ulong, 0x00002000);
pub const CKF_VERIFY_RECOVER = @as(c_ulong, 0x00004000);
pub const CKF_GENERATE = @as(c_ulong, 0x00008000);
pub const CKF_GENERATE_KEY_PAIR = @as(c_ulong, 0x00010000);
pub const CKF_WRAP = @as(c_ulong, 0x00020000);
pub const CKF_UNWRAP = @as(c_ulong, 0x00040000);
pub const CKF_DERIVE = @as(c_ulong, 0x00080000);
pub const CKF_EC_F_P = @as(c_ulong, 0x00100000);
pub const CKF_EC_F_2M = @as(c_ulong, 0x00200000);
pub const CKF_EC_ECPARAMETERS = @as(c_ulong, 0x00400000);
pub const CKF_EC_NAMEDCURVE = @as(c_ulong, 0x00800000);
pub const CKF_EC_UNCOMPRESS = @as(c_ulong, 0x01000000);
pub const CKF_EC_COMPRESS = @as(c_ulong, 0x02000000);
pub const CKF_EXTENSION = @as(c_ulong, 0x80000000);
pub const CKR_OK = @as(c_ulong, 0x00000000);
pub const CKR_CANCEL = @as(c_ulong, 0x00000001);
pub const CKR_HOST_MEMORY = @as(c_ulong, 0x00000002);
pub const CKR_SLOT_ID_INVALID = @as(c_ulong, 0x00000003);
pub const CKR_GENERAL_ERROR = @as(c_ulong, 0x00000005);
pub const CKR_FUNCTION_FAILED = @as(c_ulong, 0x00000006);
pub const CKR_ARGUMENTS_BAD = @as(c_ulong, 0x00000007);
pub const CKR_NO_EVENT = @as(c_ulong, 0x00000008);
pub const CKR_NEED_TO_CREATE_THREADS = @as(c_ulong, 0x00000009);
pub const CKR_CANT_LOCK = @as(c_ulong, 0x0000000A);
pub const CKR_ATTRIBUTE_READ_ONLY = @as(c_ulong, 0x00000010);
pub const CKR_ATTRIBUTE_SENSITIVE = @as(c_ulong, 0x00000011);
pub const CKR_ATTRIBUTE_TYPE_INVALID = @as(c_ulong, 0x00000012);
pub const CKR_ATTRIBUTE_VALUE_INVALID = @as(c_ulong, 0x00000013);
pub const CKR_ACTION_PROHIBITED = @as(c_ulong, 0x0000001B);
pub const CKR_DATA_INVALID = @as(c_ulong, 0x00000020);
pub const CKR_DATA_LEN_RANGE = @as(c_ulong, 0x00000021);
pub const CKR_DEVICE_ERROR = @as(c_ulong, 0x00000030);
pub const CKR_DEVICE_MEMORY = @as(c_ulong, 0x00000031);
pub const CKR_DEVICE_REMOVED = @as(c_ulong, 0x00000032);
pub const CKR_ENCRYPTED_DATA_INVALID = @as(c_ulong, 0x00000040);
pub const CKR_ENCRYPTED_DATA_LEN_RANGE = @as(c_ulong, 0x00000041);
pub const CKR_FUNCTION_CANCELED = @as(c_ulong, 0x00000050);
pub const CKR_FUNCTION_NOT_PARALLEL = @as(c_ulong, 0x00000051);
pub const CKR_FUNCTION_NOT_SUPPORTED = @as(c_ulong, 0x00000054);
pub const CKR_KEY_HANDLE_INVALID = @as(c_ulong, 0x00000060);
pub const CKR_KEY_SIZE_RANGE = @as(c_ulong, 0x00000062);
pub const CKR_KEY_TYPE_INCONSISTENT = @as(c_ulong, 0x00000063);
pub const CKR_KEY_NOT_NEEDED = @as(c_ulong, 0x00000064);
pub const CKR_KEY_CHANGED = @as(c_ulong, 0x00000065);
pub const CKR_KEY_NEEDED = @as(c_ulong, 0x00000066);
pub const CKR_KEY_INDIGESTIBLE = @as(c_ulong, 0x00000067);
pub const CKR_KEY_FUNCTION_NOT_PERMITTED = @as(c_ulong, 0x00000068);
pub const CKR_KEY_NOT_WRAPPABLE = @as(c_ulong, 0x00000069);
pub const CKR_KEY_UNEXTRACTABLE = @as(c_ulong, 0x0000006A);
pub const CKR_MECHANISM_INVALID = @as(c_ulong, 0x00000070);
pub const CKR_MECHANISM_PARAM_INVALID = @as(c_ulong, 0x00000071);
pub const CKR_OBJECT_HANDLE_INVALID = @as(c_ulong, 0x00000082);
pub const CKR_OPERATION_ACTIVE = @as(c_ulong, 0x00000090);
pub const CKR_OPERATION_NOT_INITIALIZED = @as(c_ulong, 0x00000091);
pub const CKR_PIN_INCORRECT = @as(c_ulong, 0x000000A0);
pub const CKR_PIN_INVALID = @as(c_ulong, 0x000000A1);
pub const CKR_PIN_LEN_RANGE = @as(c_ulong, 0x000000A2);
pub const CKR_PIN_EXPIRED = @as(c_ulong, 0x000000A3);
pub const CKR_PIN_LOCKED = @as(c_ulong, 0x000000A4);
pub const CKR_SESSION_CLOSED = @as(c_ulong, 0x000000B0);
pub const CKR_SESSION_COUNT = @as(c_ulong, 0x000000B1);
pub const CKR_SESSION_HANDLE_INVALID = @as(c_ulong, 0x000000B3);
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED = @as(c_ulong, 0x000000B4);
pub const CKR_SESSION_READ_ONLY = @as(c_ulong, 0x000000B5);
pub const CKR_SESSION_EXISTS = @as(c_ulong, 0x000000B6);
pub const CKR_SESSION_READ_ONLY_EXISTS = @as(c_ulong, 0x000000B7);
pub const CKR_SESSION_READ_WRITE_SO_EXISTS = @as(c_ulong, 0x000000B8);
pub const CKR_SIGNATURE_INVALID = @as(c_ulong, 0x000000C0);
pub const CKR_SIGNATURE_LEN_RANGE = @as(c_ulong, 0x000000C1);
pub const CKR_TEMPLATE_INCOMPLETE = @as(c_ulong, 0x000000D0);
pub const CKR_TEMPLATE_INCONSISTENT = @as(c_ulong, 0x000000D1);
pub const CKR_TOKEN_NOT_PRESENT = @as(c_ulong, 0x000000E0);
pub const CKR_TOKEN_NOT_RECOGNIZED = @as(c_ulong, 0x000000E1);
pub const CKR_TOKEN_WRITE_PROTECTED = @as(c_ulong, 0x000000E2);
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID = @as(c_ulong, 0x000000F0);
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE = @as(c_ulong, 0x000000F1);
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = @as(c_ulong, 0x000000F2);
pub const CKR_USER_ALREADY_LOGGED_IN = @as(c_ulong, 0x00000100);
pub const CKR_USER_NOT_LOGGED_IN = @as(c_ulong, 0x00000101);
pub const CKR_USER_PIN_NOT_INITIALIZED = @as(c_ulong, 0x00000102);
pub const CKR_USER_TYPE_INVALID = @as(c_ulong, 0x00000103);
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN = @as(c_ulong, 0x00000104);
pub const CKR_USER_TOO_MANY_TYPES = @as(c_ulong, 0x00000105);
pub const CKR_WRAPPED_KEY_INVALID = @as(c_ulong, 0x00000110);
pub const CKR_WRAPPED_KEY_LEN_RANGE = @as(c_ulong, 0x00000112);
pub const CKR_WRAPPING_KEY_HANDLE_INVALID = @as(c_ulong, 0x00000113);
pub const CKR_WRAPPING_KEY_SIZE_RANGE = @as(c_ulong, 0x00000114);
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT = @as(c_ulong, 0x00000115);
pub const CKR_RANDOM_SEED_NOT_SUPPORTED = @as(c_ulong, 0x00000120);
pub const CKR_RANDOM_NO_RNG = @as(c_ulong, 0x00000121);
pub const CKR_DOMAIN_PARAMS_INVALID = @as(c_ulong, 0x00000130);
pub const CKR_CURVE_NOT_SUPPORTED = @as(c_ulong, 0x00000140);
pub const CKR_BUFFER_TOO_SMALL = @as(c_ulong, 0x00000150);
pub const CKR_SAVED_STATE_INVALID = @as(c_ulong, 0x00000160);
pub const CKR_INFORMATION_SENSITIVE = @as(c_ulong, 0x00000170);
pub const CKR_STATE_UNSAVEABLE = @as(c_ulong, 0x00000180);
pub const CKR_CRYPTOKI_NOT_INITIALIZED = @as(c_ulong, 0x00000190);
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED = @as(c_ulong, 0x00000191);
pub const CKR_MUTEX_BAD = @as(c_ulong, 0x000001A0);
pub const CKR_MUTEX_NOT_LOCKED = @as(c_ulong, 0x000001A1);
pub const CKR_NEW_PIN_MODE = @as(c_ulong, 0x000001B0);
pub const CKR_NEXT_OTP = @as(c_ulong, 0x000001B1);
pub const CKR_EXCEEDED_MAX_ITERATIONS = @as(c_ulong, 0x000001B5);
pub const CKR_FIPS_SELF_TEST_FAILED = @as(c_ulong, 0x000001B6);
pub const CKR_LIBRARY_LOAD_FAILED = @as(c_ulong, 0x000001B7);
pub const CKR_PIN_TOO_WEAK = @as(c_ulong, 0x000001B8);
pub const CKR_PUBLIC_KEY_INVALID = @as(c_ulong, 0x000001B9);
pub const CKR_FUNCTION_REJECTED = @as(c_ulong, 0x00000200);
pub const CKR_VENDOR_DEFINED = @as(c_ulong, 0x80000000);
pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS = @as(c_ulong, 0x00000001);
pub const CKF_OS_LOCKING_OK = @as(c_ulong, 0x00000002);
pub const CKF_DONT_BLOCK = @as(c_int, 1);
pub const CKG_MGF1_SHA1 = @as(c_ulong, 0x00000001);
pub const CKG_MGF1_SHA256 = @as(c_ulong, 0x00000002);
pub const CKG_MGF1_SHA384 = @as(c_ulong, 0x00000003);
pub const CKG_MGF1_SHA512 = @as(c_ulong, 0x00000004);
pub const CKG_MGF1_SHA224 = @as(c_ulong, 0x00000005);
pub const CKZ_DATA_SPECIFIED = @as(c_ulong, 0x00000001);
pub const CKD_NULL = @as(c_ulong, 0x00000001);
pub const CKD_SHA1_KDF = @as(c_ulong, 0x00000002);
pub const CKD_SHA1_KDF_ASN1 = @as(c_ulong, 0x00000003);
pub const CKD_SHA1_KDF_CONCATENATE = @as(c_ulong, 0x00000004);
pub const CKD_SHA224_KDF = @as(c_ulong, 0x00000005);
pub const CKD_SHA256_KDF = @as(c_ulong, 0x00000006);
pub const CKD_SHA384_KDF = @as(c_ulong, 0x00000007);
pub const CKD_SHA512_KDF = @as(c_ulong, 0x00000008);
pub const CKD_CPDIVERSIFY_KDF = @as(c_ulong, 0x00000009);
pub const CKD_SHA3_224_KDF = @as(c_ulong, 0x0000000A);
pub const CKD_SHA3_256_KDF = @as(c_ulong, 0x0000000B);
pub const CKD_SHA3_384_KDF = @as(c_ulong, 0x0000000C);
pub const CKD_SHA3_512_KDF = @as(c_ulong, 0x0000000D);
pub const CKP_PKCS5_PBKD2_HMAC_SHA1 = @as(c_ulong, 0x00000001);
pub const CKP_PKCS5_PBKD2_HMAC_GOSTR3411 = @as(c_ulong, 0x00000002);
pub const CKP_PKCS5_PBKD2_HMAC_SHA224 = @as(c_ulong, 0x00000003);
pub const CKP_PKCS5_PBKD2_HMAC_SHA256 = @as(c_ulong, 0x00000004);
pub const CKP_PKCS5_PBKD2_HMAC_SHA384 = @as(c_ulong, 0x00000005);
pub const CKP_PKCS5_PBKD2_HMAC_SHA512 = @as(c_ulong, 0x00000006);
pub const CKP_PKCS5_PBKD2_HMAC_SHA512_224 = @as(c_ulong, 0x00000007);
pub const CKP_PKCS5_PBKD2_HMAC_SHA512_256 = @as(c_ulong, 0x00000008);
pub const CKZ_SALT_SPECIFIED = @as(c_ulong, 0x00000001);
pub const CK_OTP_VALUE = @as(c_ulong, 0);
pub const CK_OTP_PIN = @as(c_ulong, 1);
pub const CK_OTP_CHALLENGE = @as(c_ulong, 2);
pub const CK_OTP_TIME = @as(c_ulong, 3);
pub const CK_OTP_COUNTER = @as(c_ulong, 4);
pub const CK_OTP_FLAGS = @as(c_ulong, 5);
pub const CK_OTP_OUTPUT_LENGTH = @as(c_ulong, 6);
pub const CK_OTP_OUTPUT_FORMAT = @as(c_ulong, 7);
pub const CKF_NEXT_OTP = @as(c_ulong, 0x00000001);
pub const CKF_EXCLUDE_TIME = @as(c_ulong, 0x00000002);
pub const CKF_EXCLUDE_COUNTER = @as(c_ulong, 0x00000004);
pub const CKF_EXCLUDE_CHALLENGE = @as(c_ulong, 0x00000008);
pub const CKF_EXCLUDE_PIN = @as(c_ulong, 0x00000010);
pub const CKF_USER_FRIENDLY_OTP = @as(c_ulong, 0x00000020);
pub const CK_NEED_ARG_LIST = @as(c_int, 1);
