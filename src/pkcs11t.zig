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
pub const CK_EC_KDF_TYPE = CK_ULONG;
pub const CK_X9_42_DH_KDF_TYPE = CK_ULONG;
pub const CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG;
pub const CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG;

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

pub const CK_VOID_PTR = ?*CK_VOID;
pub const CK_BYTE_PTR = ?*CK_BYTE;
pub const CK_OBJECT_HANDLE = CK_ULONG;
pub const CK_X2RATCHET_KDF_TYPE = CK_ULONG;
pub const CK_X3DH_KDF_TYPE = CK_ULONG;
pub const CK_X2RATCHET_KDF_TYPE_PTR = CK_X2RATCHET_KDF_TYPE;
pub const CK_TRUE = @as(c_int, 1);
pub const CK_FALSE = @as(c_int, 0);
pub const CK_EFFECTIVELY_INFINITE = @as(c_int, 0);
pub const CK_INVALID_HANDLE = @as(c_int, 0);
pub const CKN_SURRENDER = @as(c_int, 0);
pub const CKN_OTP_CHANGED = @as(c_int, 1);
pub const CKF_TOKEN_PRESENT = @as(c_int, 1);
pub const CKF_REMOVABLE_DEVICE = @as(c_int, 2);
pub const CKF_HW_SLOT = @as(c_int, 4);
pub const CKF_RNG = @as(c_int, 1);
pub const CKF_WRITE_PROTECTED = @as(c_int, 2);
pub const CKF_LOGIN_REQUIRED = @as(c_int, 4);
pub const CKF_USER_PIN_INITIALIZED = @as(c_int, 8);
pub const CKF_RESTORE_KEY_NOT_NEEDED = @as(c_int, 32);
pub const CKF_CLOCK_ON_TOKEN = @as(c_int, 64);
pub const CKF_PROTECTED_AUTHENTICATION_PATH = @as(c_int, 256);
pub const CKF_DUAL_CRYPTO_OPERATIONS = @as(c_int, 512);
pub const CKF_TOKEN_INITIALIZED = @as(c_int, 1024);
pub const CKF_SECONDARY_AUTHENTICATION = @as(c_int, 2048);
pub const CKF_USER_PIN_COUNT_LOW = c.promoteIntLiteral(c_int, 65536, .decimal);
pub const CKF_USER_PIN_FINAL_TRY = c.promoteIntLiteral(c_int, 131072, .decimal);
pub const CKF_USER_PIN_LOCKED = c.promoteIntLiteral(c_int, 262144, .decimal);
pub const CKF_USER_PIN_TO_BE_CHANGED = c.promoteIntLiteral(c_int, 524288, .decimal);
pub const CKF_SO_PIN_COUNT_LOW = c.promoteIntLiteral(c_int, 1048576, .decimal);
pub const CKF_SO_PIN_FINAL_TRY = c.promoteIntLiteral(c_int, 2097152, .decimal);
pub const CKF_SO_PIN_LOCKED = c.promoteIntLiteral(c_int, 4194304, .decimal);
pub const CKF_SO_PIN_TO_BE_CHANGED = c.promoteIntLiteral(c_int, 8388608, .decimal);
pub const CKF_ERROR_STATE = c.promoteIntLiteral(c_int, 16777216, .decimal);
pub const CKU_SO = @as(c_int, 0);
pub const CKU_USER = @as(c_int, 1);
pub const CKU_CONTEXT_SPECIFIC = @as(c_int, 2);
pub const CKS_RO_PUBLIC_SESSION = @as(c_int, 0);
pub const CKS_RO_USER_FUNCTIONS = @as(c_int, 1);
pub const CKS_RW_PUBLIC_SESSION = @as(c_int, 2);
pub const CKS_RW_USER_FUNCTIONS = @as(c_int, 3);
pub const CKS_RW_SO_FUNCTIONS = @as(c_int, 4);
pub const CKF_RW_SESSION = @as(c_int, 2);
pub const CKF_SERIAL_SESSION = @as(c_int, 4);
pub const CKO_DATA = @as(c_int, 0);
pub const CKO_CERTIFICATE = @as(c_int, 1);
pub const CKO_PUBLIC_KEY = @as(c_int, 2);
pub const CKO_PRIVATE_KEY = @as(c_int, 3);
pub const CKO_SECRET_KEY = @as(c_int, 4);
pub const CKO_HW_FEATURE = @as(c_int, 5);
pub const CKO_DOMAIN_PARAMETERS = @as(c_int, 6);
pub const CKO_MECHANISM = @as(c_int, 7);
pub const CKO_OTP_KEY = @as(c_int, 8);
pub const CKO_VENDOR_DEFINED = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CKH_MONOTONIC_COUNTER = @as(c_int, 1);
pub const CKH_CLOCK = @as(c_int, 2);
pub const CKH_USER_INTERFACE = @as(c_int, 3);
pub const CKH_VENDOR_DEFINED = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CKK_RSA = @as(c_int, 0);
pub const CKK_DSA = @as(c_int, 1);
pub const CKK_DH = @as(c_int, 2);
pub const CKK_ECDSA = CKK_EC;
pub const CKK_EC = @as(c_int, 3);
pub const CKK_X9_42_DH = @as(c_int, 4);
pub const CKK_KEA = @as(c_int, 5);
pub const CKK_GENERIC_SECRET = @as(c_int, 16);
pub const CKK_RC2 = @as(c_int, 17);
pub const CKK_RC4 = @as(c_int, 18);
pub const CKK_DES = @as(c_int, 19);
pub const CKK_DES2 = @as(c_int, 20);
pub const CKK_DES3 = @as(c_int, 21);
pub const CKK_CAST = @as(c_int, 22);
pub const CKK_CAST3 = @as(c_int, 23);
pub const CKK_CAST5 = CKK_CAST128;
pub const CKK_CAST128 = @as(c_int, 24);
pub const CKK_RC5 = @as(c_int, 25);
pub const CKK_IDEA = @as(c_int, 26);
pub const CKK_SKIPJACK = @as(c_int, 27);
pub const CKK_BATON = @as(c_int, 28);
pub const CKK_JUNIPER = @as(c_int, 29);
pub const CKK_CDMF = @as(c_int, 30);
pub const CKK_AES = @as(c_int, 31);
pub const CKK_BLOWFISH = @as(c_int, 32);
pub const CKK_TWOFISH = @as(c_int, 33);
pub const CKK_SECURID = @as(c_int, 34);
pub const CKK_HOTP = @as(c_int, 35);
pub const CKK_ACTI = @as(c_int, 36);
pub const CKK_CAMELLIA = @as(c_int, 37);
pub const CKK_ARIA = @as(c_int, 38);
pub const CKK_MD5_HMAC = @as(c_int, 39);
pub const CKK_SHA_1_HMAC = @as(c_int, 40);
pub const CKK_RIPEMD128_HMAC = @as(c_int, 41);
pub const CKK_RIPEMD160_HMAC = @as(c_int, 42);
pub const CKK_SHA256_HMAC = @as(c_int, 43);
pub const CKK_SHA384_HMAC = @as(c_int, 44);
pub const CKK_SHA512_HMAC = @as(c_int, 45);
pub const CKK_SHA224_HMAC = @as(c_int, 46);
pub const CKK_SEED = @as(c_int, 47);
pub const CKK_GOSTR3410 = @as(c_int, 48);
pub const CKK_GOSTR3411 = @as(c_int, 49);
pub const CKK_GOST28147 = @as(c_int, 50);
pub const CKK_VENDOR_DEFINED = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CK_CERTIFICATE_CATEGORY_UNSPECIFIED = @as(c_int, 0);
pub const CK_CERTIFICATE_CATEGORY_TOKEN_USER = @as(c_int, 1);
pub const CK_CERTIFICATE_CATEGORY_AUTHORITY = @as(c_int, 2);
pub const CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = @as(c_int, 3);
pub const CK_SECURITY_DOMAIN_UNSPECIFIED = @as(c_int, 0);
pub const CK_SECURITY_DOMAIN_MANUFACTURER = @as(c_int, 1);
pub const CK_SECURITY_DOMAIN_OPERATOR = @as(c_int, 2);
pub const CK_SECURITY_DOMAIN_THIRD_PARTY = @as(c_int, 3);
pub const CKC_X_509 = @as(c_int, 0);
pub const CKC_X_509_ATTR_CERT = @as(c_int, 1);
pub const CKC_WTLS = @as(c_int, 2);
pub const CKC_VENDOR_DEFINED = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CKF_ARRAY_ATTRIBUTE = c.promoteIntLiteral(c_int, 1073741824, .decimal);
pub const CK_OTP_FORMAT_DECIMAL = @as(c_int, 0);
pub const CK_OTP_FORMAT_HEXADECIMAL = @as(c_int, 1);
pub const CK_OTP_FORMAT_ALPHANUMERIC = @as(c_int, 2);
pub const CK_OTP_FORMAT_BINARY = @as(c_int, 3);
pub const CK_OTP_PARAM_IGNORED = @as(c_int, 0);
pub const CK_OTP_PARAM_OPTIONAL = @as(c_int, 1);
pub const CK_OTP_PARAM_MANDATORY = @as(c_int, 2);
pub const CKA_CLASS = @as(c_int, 0);
pub const CKA_TOKEN = @as(c_int, 1);
pub const CKA_PRIVATE = @as(c_int, 2);
pub const CKA_LABEL = @as(c_int, 3);
pub const CKA_APPLICATION = @as(c_int, 16);
pub const CKA_VALUE = @as(c_int, 17);
pub const CKA_OBJECT_ID = @as(c_int, 18);
pub const CKA_CERTIFICATE_TYPE = @as(c_int, 128);
pub const CKA_ISSUER = @as(c_int, 129);
pub const CKA_SERIAL_NUMBER = @as(c_int, 130);
pub const CKA_AC_ISSUER = @as(c_int, 131);
pub const CKA_OWNER = @as(c_int, 132);
pub const CKA_ATTR_TYPES = @as(c_int, 133);
pub const CKA_TRUSTED = @as(c_int, 134);
pub const CKA_CERTIFICATE_CATEGORY = @as(c_int, 135);
pub const CKA_JAVA_MIDP_SECURITY_DOMAIN = @as(c_int, 136);
pub const CKA_URL = @as(c_int, 137);
pub const CKA_HASH_OF_SUBJECT_PUBLIC_KEY = @as(c_int, 138);
pub const CKA_HASH_OF_ISSUER_PUBLIC_KEY = @as(c_int, 139);
pub const CKA_NAME_HASH_ALGORITHM = @as(c_int, 140);
pub const CKA_CHECK_VALUE = @as(c_int, 144);
pub const CKA_KEY_TYPE = @as(c_int, 256);
pub const CKA_SUBJECT = @as(c_int, 257);
pub const CKA_ID = @as(c_int, 258);
pub const CKA_SENSITIVE = @as(c_int, 259);
pub const CKA_ENCRYPT = @as(c_int, 260);
pub const CKA_DECRYPT = @as(c_int, 261);
pub const CKA_WRAP = @as(c_int, 262);
pub const CKA_UNWRAP = @as(c_int, 263);
pub const CKA_SIGN = @as(c_int, 264);
pub const CKA_SIGN_RECOVER = @as(c_int, 265);
pub const CKA_VERIFY = @as(c_int, 266);
pub const CKA_VERIFY_RECOVER = @as(c_int, 267);
pub const CKA_DERIVE = @as(c_int, 268);
pub const CKA_START_DATE = @as(c_int, 272);
pub const CKA_END_DATE = @as(c_int, 273);
pub const CKA_MODULUS = @as(c_int, 288);
pub const CKA_MODULUS_BITS = @as(c_int, 289);
pub const CKA_PUBLIC_EXPONENT = @as(c_int, 290);
pub const CKA_PRIVATE_EXPONENT = @as(c_int, 291);
pub const CKA_PRIME_1 = @as(c_int, 292);
pub const CKA_PRIME_2 = @as(c_int, 293);
pub const CKA_EXPONENT_1 = @as(c_int, 294);
pub const CKA_EXPONENT_2 = @as(c_int, 295);
pub const CKA_COEFFICIENT = @as(c_int, 296);
pub const CKA_PUBLIC_KEY_INFO = @as(c_int, 297);
pub const CKA_PRIME = @as(c_int, 304);
pub const CKA_SUBPRIME = @as(c_int, 305);
pub const CKA_BASE = @as(c_int, 306);
pub const CKA_PRIME_BITS = @as(c_int, 307);
pub const CKA_SUBPRIME_BITS = @as(c_int, 308);
pub const CKA_SUB_PRIME_BITS = CKA_SUBPRIME_BITS;
pub const CKA_VALUE_BITS = @as(c_int, 352);
pub const CKA_VALUE_LEN = @as(c_int, 353);
pub const CKA_EXTRACTABLE = @as(c_int, 354);
pub const CKA_LOCAL = @as(c_int, 355);
pub const CKA_NEVER_EXTRACTABLE = @as(c_int, 356);
pub const CKA_ALWAYS_SENSITIVE = @as(c_int, 357);
pub const CKA_KEY_GEN_MECHANISM = @as(c_int, 358);
pub const CKA_MODIFIABLE = @as(c_int, 368);
pub const CKA_COPYABLE = @as(c_int, 369);
pub const CKA_DESTROYABLE = @as(c_int, 370);
pub const CKA_ECDSA_PARAMS = CKA_EC_PARAMS;
pub const CKA_EC_PARAMS = @as(c_int, 384);
pub const CKA_EC_POINT = @as(c_int, 385);
pub const CKA_SECONDARY_AUTH = @as(c_int, 512);
pub const CKA_AUTH_PIN_FLAGS = @as(c_int, 513);
pub const CKA_ALWAYS_AUTHENTICATE = @as(c_int, 514);
pub const CKA_WRAP_WITH_TRUSTED = @as(c_int, 528);
pub const CKA_WRAP_TEMPLATE = CKF_ARRAY_ATTRIBUTE | @as(c_int, 529);
pub const CKA_UNWRAP_TEMPLATE = CKF_ARRAY_ATTRIBUTE | @as(c_int, 530);
pub const CKA_DERIVE_TEMPLATE = CKF_ARRAY_ATTRIBUTE | @as(c_int, 531);
pub const CKA_OTP_FORMAT = @as(c_int, 544);
pub const CKA_OTP_LENGTH = @as(c_int, 545);
pub const CKA_OTP_TIME_INTERVAL = @as(c_int, 546);
pub const CKA_OTP_USER_FRIENDLY_MODE = @as(c_int, 547);
pub const CKA_OTP_CHALLENGE_REQUIREMENT = @as(c_int, 548);
pub const CKA_OTP_TIME_REQUIREMENT = @as(c_int, 549);
pub const CKA_OTP_COUNTER_REQUIREMENT = @as(c_int, 550);
pub const CKA_OTP_PIN_REQUIREMENT = @as(c_int, 551);
pub const CKA_OTP_COUNTER = @as(c_int, 558);
pub const CKA_OTP_TIME = @as(c_int, 559);
pub const CKA_OTP_USER_IDENTIFIER = @as(c_int, 554);
pub const CKA_OTP_SERVICE_IDENTIFIER = @as(c_int, 555);
pub const CKA_OTP_SERVICE_LOGO = @as(c_int, 556);
pub const CKA_OTP_SERVICE_LOGO_TYPE = @as(c_int, 557);
pub const CKA_GOSTR3410_PARAMS = @as(c_int, 592);
pub const CKA_GOSTR3411_PARAMS = @as(c_int, 593);
pub const CKA_GOST28147_PARAMS = @as(c_int, 594);
pub const CKA_HW_FEATURE_TYPE = @as(c_int, 768);
pub const CKA_RESET_ON_INIT = @as(c_int, 769);
pub const CKA_HAS_RESET = @as(c_int, 770);
pub const CKA_PIXEL_X = @as(c_int, 1024);
pub const CKA_PIXEL_Y = @as(c_int, 1025);
pub const CKA_RESOLUTION = @as(c_int, 1026);
pub const CKA_CHAR_ROWS = @as(c_int, 1027);
pub const CKA_CHAR_COLUMNS = @as(c_int, 1028);
pub const CKA_COLOR = @as(c_int, 1029);
pub const CKA_BITS_PER_PIXEL = @as(c_int, 1030);
pub const CKA_CHAR_SETS = @as(c_int, 1152);
pub const CKA_ENCODING_METHODS = @as(c_int, 1153);
pub const CKA_MIME_TYPES = @as(c_int, 1154);
pub const CKA_MECHANISM_TYPE = @as(c_int, 1280);
pub const CKA_REQUIRED_CMS_ATTRIBUTES = @as(c_int, 1281);
pub const CKA_DEFAULT_CMS_ATTRIBUTES = @as(c_int, 1282);
pub const CKA_SUPPORTED_CMS_ATTRIBUTES = @as(c_int, 1283);
pub const CKA_ALLOWED_MECHANISMS = CKF_ARRAY_ATTRIBUTE | @as(c_int, 1536);
pub const CKA_VENDOR_DEFINED = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CKM_RSA_PKCS_KEY_PAIR_GEN = @as(c_int, 0);
pub const CKM_RSA_PKCS = @as(c_int, 1);
pub const CKM_RSA_9796 = @as(c_int, 2);
pub const CKM_RSA_X_509 = @as(c_int, 3);
pub const CKM_MD2_RSA_PKCS = @as(c_int, 4);
pub const CKM_MD5_RSA_PKCS = @as(c_int, 5);
pub const CKM_SHA1_RSA_PKCS = @as(c_int, 6);
pub const CKM_RIPEMD128_RSA_PKCS = @as(c_int, 7);
pub const CKM_RIPEMD160_RSA_PKCS = @as(c_int, 8);
pub const CKM_RSA_PKCS_OAEP = @as(c_int, 9);
pub const CKM_RSA_X9_31_KEY_PAIR_GEN = @as(c_int, 10);
pub const CKM_RSA_X9_31 = @as(c_int, 11);
pub const CKM_SHA1_RSA_X9_31 = @as(c_int, 12);
pub const CKM_RSA_PKCS_PSS = @as(c_int, 13);
pub const CKM_SHA1_RSA_PKCS_PSS = @as(c_int, 14);
pub const CKM_DSA_KEY_PAIR_GEN = @as(c_int, 16);
pub const CKM_DSA = @as(c_int, 17);
pub const CKM_DSA_SHA1 = @as(c_int, 18);
pub const CKM_DSA_SHA224 = @as(c_int, 19);
pub const CKM_DSA_SHA256 = @as(c_int, 20);
pub const CKM_DSA_SHA384 = @as(c_int, 21);
pub const CKM_DSA_SHA512 = @as(c_int, 22);
pub const CKM_DH_PKCS_KEY_PAIR_GEN = @as(c_int, 32);
pub const CKM_DH_PKCS_DERIVE = @as(c_int, 33);
pub const CKM_X9_42_DH_KEY_PAIR_GEN = @as(c_int, 48);
pub const CKM_X9_42_DH_DERIVE = @as(c_int, 49);
pub const CKM_X9_42_DH_HYBRID_DERIVE = @as(c_int, 50);
pub const CKM_X9_42_MQV_DERIVE = @as(c_int, 51);
pub const CKM_SHA256_RSA_PKCS = @as(c_int, 64);
pub const CKM_SHA384_RSA_PKCS = @as(c_int, 65);
pub const CKM_SHA512_RSA_PKCS = @as(c_int, 66);
pub const CKM_SHA256_RSA_PKCS_PSS = @as(c_int, 67);
pub const CKM_SHA384_RSA_PKCS_PSS = @as(c_int, 68);
pub const CKM_SHA512_RSA_PKCS_PSS = @as(c_int, 69);
pub const CKM_SHA224_RSA_PKCS = @as(c_int, 70);
pub const CKM_SHA224_RSA_PKCS_PSS = @as(c_int, 71);
pub const CKM_SHA512_224 = @as(c_int, 72);
pub const CKM_SHA512_224_HMAC = @as(c_int, 73);
pub const CKM_SHA512_224_HMAC_GENERAL = @as(c_int, 74);
pub const CKM_SHA512_224_KEY_DERIVATION = @as(c_int, 75);
pub const CKM_SHA512_256 = @as(c_int, 76);
pub const CKM_SHA512_256_HMAC = @as(c_int, 77);
pub const CKM_SHA512_256_HMAC_GENERAL = @as(c_int, 78);
pub const CKM_SHA512_256_KEY_DERIVATION = @as(c_int, 79);
pub const CKM_SHA512_T = @as(c_int, 80);
pub const CKM_SHA512_T_HMAC = @as(c_int, 81);
pub const CKM_SHA512_T_HMAC_GENERAL = @as(c_int, 82);
pub const CKM_SHA512_T_KEY_DERIVATION = @as(c_int, 83);
pub const CKM_RC2_KEY_GEN = @as(c_int, 256);
pub const CKM_RC2_ECB = @as(c_int, 257);
pub const CKM_RC2_CBC = @as(c_int, 258);
pub const CKM_RC2_MAC = @as(c_int, 259);
pub const CKM_RC2_MAC_GENERAL = @as(c_int, 260);
pub const CKM_RC2_CBC_PAD = @as(c_int, 261);
pub const CKM_RC4_KEY_GEN = @as(c_int, 272);
pub const CKM_RC4 = @as(c_int, 273);
pub const CKM_DES_KEY_GEN = @as(c_int, 288);
pub const CKM_DES_ECB = @as(c_int, 289);
pub const CKM_DES_CBC = @as(c_int, 290);
pub const CKM_DES_MAC = @as(c_int, 291);
pub const CKM_DES_MAC_GENERAL = @as(c_int, 292);
pub const CKM_DES_CBC_PAD = @as(c_int, 293);
pub const CKM_DES2_KEY_GEN = @as(c_int, 304);
pub const CKM_DES3_KEY_GEN = @as(c_int, 305);
pub const CKM_DES3_ECB = @as(c_int, 306);
pub const CKM_DES3_CBC = @as(c_int, 307);
pub const CKM_DES3_MAC = @as(c_int, 308);
pub const CKM_DES3_MAC_GENERAL = @as(c_int, 309);
pub const CKM_DES3_CBC_PAD = @as(c_int, 310);
pub const CKM_DES3_CMAC_GENERAL = @as(c_int, 311);
pub const CKM_DES3_CMAC = @as(c_int, 312);
pub const CKM_CDMF_KEY_GEN = @as(c_int, 320);
pub const CKM_CDMF_ECB = @as(c_int, 321);
pub const CKM_CDMF_CBC = @as(c_int, 322);
pub const CKM_CDMF_MAC = @as(c_int, 323);
pub const CKM_CDMF_MAC_GENERAL = @as(c_int, 324);
pub const CKM_CDMF_CBC_PAD = @as(c_int, 325);
pub const CKM_DES_OFB64 = @as(c_int, 336);
pub const CKM_DES_OFB8 = @as(c_int, 337);
pub const CKM_DES_CFB64 = @as(c_int, 338);
pub const CKM_DES_CFB8 = @as(c_int, 339);
pub const CKM_MD2 = @as(c_int, 512);
pub const CKM_MD2_HMAC = @as(c_int, 513);
pub const CKM_MD2_HMAC_GENERAL = @as(c_int, 514);
pub const CKM_MD5 = @as(c_int, 528);
pub const CKM_MD5_HMAC = @as(c_int, 529);
pub const CKM_MD5_HMAC_GENERAL = @as(c_int, 530);
pub const CKM_SHA_1 = @as(c_int, 544);
pub const CKM_SHA_1_HMAC = @as(c_int, 545);
pub const CKM_SHA_1_HMAC_GENERAL = @as(c_int, 546);
pub const CKM_RIPEMD128 = @as(c_int, 560);
pub const CKM_RIPEMD128_HMAC = @as(c_int, 561);
pub const CKM_RIPEMD128_HMAC_GENERAL = @as(c_int, 562);
pub const CKM_RIPEMD160 = @as(c_int, 576);
pub const CKM_RIPEMD160_HMAC = @as(c_int, 577);
pub const CKM_RIPEMD160_HMAC_GENERAL = @as(c_int, 578);
pub const CKM_SHA256 = @as(c_int, 592);
pub const CKM_SHA256_HMAC = @as(c_int, 593);
pub const CKM_SHA256_HMAC_GENERAL = @as(c_int, 594);
pub const CKM_SHA224 = @as(c_int, 597);
pub const CKM_SHA224_HMAC = @as(c_int, 598);
pub const CKM_SHA224_HMAC_GENERAL = @as(c_int, 599);
pub const CKM_SHA384 = @as(c_int, 608);
pub const CKM_SHA384_HMAC = @as(c_int, 609);
pub const CKM_SHA384_HMAC_GENERAL = @as(c_int, 610);
pub const CKM_SHA512 = @as(c_int, 624);
pub const CKM_SHA512_HMAC = @as(c_int, 625);
pub const CKM_SHA512_HMAC_GENERAL = @as(c_int, 626);
pub const CKM_SECURID_KEY_GEN = @as(c_int, 640);
pub const CKM_SECURID = @as(c_int, 642);
pub const CKM_HOTP_KEY_GEN = @as(c_int, 656);
pub const CKM_HOTP = @as(c_int, 657);
pub const CKM_ACTI = @as(c_int, 672);
pub const CKM_ACTI_KEY_GEN = @as(c_int, 673);
pub const CKM_CAST_KEY_GEN = @as(c_int, 768);
pub const CKM_CAST_ECB = @as(c_int, 769);
pub const CKM_CAST_CBC = @as(c_int, 770);
pub const CKM_CAST_MAC = @as(c_int, 771);
pub const CKM_CAST_MAC_GENERAL = @as(c_int, 772);
pub const CKM_CAST_CBC_PAD = @as(c_int, 773);
pub const CKM_CAST3_KEY_GEN = @as(c_int, 784);
pub const CKM_CAST3_ECB = @as(c_int, 785);
pub const CKM_CAST3_CBC = @as(c_int, 786);
pub const CKM_CAST3_MAC = @as(c_int, 787);
pub const CKM_CAST3_MAC_GENERAL = @as(c_int, 788);
pub const CKM_CAST3_CBC_PAD = @as(c_int, 789);
pub const CKM_CAST5_KEY_GEN = @as(c_int, 800);
pub const CKM_CAST128_KEY_GEN = @as(c_int, 800);
pub const CKM_CAST5_ECB = @as(c_int, 801);
pub const CKM_CAST128_ECB = @as(c_int, 801);
pub const CKM_CAST5_CBC = CKM_CAST128_CBC;
pub const CKM_CAST128_CBC = @as(c_int, 802);
pub const CKM_CAST5_MAC = CKM_CAST128_MAC;
pub const CKM_CAST128_MAC = @as(c_int, 803);
pub const CKM_CAST5_MAC_GENERAL = CKM_CAST128_MAC_GENERAL;
pub const CKM_CAST128_MAC_GENERAL = @as(c_int, 804);
pub const CKM_CAST5_CBC_PAD = CKM_CAST128_CBC_PAD;
pub const CKM_CAST128_CBC_PAD = @as(c_int, 805);
pub const CKM_RC5_KEY_GEN = @as(c_int, 816);
pub const CKM_RC5_ECB = @as(c_int, 817);
pub const CKM_RC5_CBC = @as(c_int, 818);
pub const CKM_RC5_MAC = @as(c_int, 819);
pub const CKM_RC5_MAC_GENERAL = @as(c_int, 820);
pub const CKM_RC5_CBC_PAD = @as(c_int, 821);
pub const CKM_IDEA_KEY_GEN = @as(c_int, 832);
pub const CKM_IDEA_ECB = @as(c_int, 833);
pub const CKM_IDEA_CBC = @as(c_int, 834);
pub const CKM_IDEA_MAC = @as(c_int, 835);
pub const CKM_IDEA_MAC_GENERAL = @as(c_int, 836);
pub const CKM_IDEA_CBC_PAD = @as(c_int, 837);
pub const CKM_GENERIC_SECRET_KEY_GEN = @as(c_int, 848);
pub const CKM_CONCATENATE_BASE_AND_KEY = @as(c_int, 864);
pub const CKM_CONCATENATE_BASE_AND_DATA = @as(c_int, 866);
pub const CKM_CONCATENATE_DATA_AND_BASE = @as(c_int, 867);
pub const CKM_XOR_BASE_AND_DATA = @as(c_int, 868);
pub const CKM_EXTRACT_KEY_FROM_KEY = @as(c_int, 869);
pub const CKM_SSL3_PRE_MASTER_KEY_GEN = @as(c_int, 880);
pub const CKM_SSL3_MASTER_KEY_DERIVE = @as(c_int, 881);
pub const CKM_SSL3_KEY_AND_MAC_DERIVE = @as(c_int, 882);
pub const CKM_SSL3_MASTER_KEY_DERIVE_DH = @as(c_int, 883);
pub const CKM_TLS_PRE_MASTER_KEY_GEN = @as(c_int, 884);
pub const CKM_TLS_MASTER_KEY_DERIVE = @as(c_int, 885);
pub const CKM_TLS_KEY_AND_MAC_DERIVE = @as(c_int, 886);
pub const CKM_TLS_MASTER_KEY_DERIVE_DH = @as(c_int, 887);
pub const CKM_TLS_PRF = @as(c_int, 888);
pub const CKM_SSL3_MD5_MAC = @as(c_int, 896);
pub const CKM_SSL3_SHA1_MAC = @as(c_int, 897);
pub const CKM_MD5_KEY_DERIVATION = @as(c_int, 912);
pub const CKM_MD2_KEY_DERIVATION = @as(c_int, 913);
pub const CKM_SHA1_KEY_DERIVATION = @as(c_int, 914);
pub const CKM_SHA256_KEY_DERIVATION = @as(c_int, 915);
pub const CKM_SHA384_KEY_DERIVATION = @as(c_int, 916);
pub const CKM_SHA512_KEY_DERIVATION = @as(c_int, 917);
pub const CKM_SHA224_KEY_DERIVATION = @as(c_int, 918);
pub const CKM_PBE_MD2_DES_CBC = @as(c_int, 928);
pub const CKM_PBE_MD5_DES_CBC = @as(c_int, 929);
pub const CKM_PBE_MD5_CAST_CBC = @as(c_int, 930);
pub const CKM_PBE_MD5_CAST3_CBC = @as(c_int, 931);
pub const CKM_PBE_MD5_CAST5_CBC = CKM_PBE_MD5_CAST128_CBC;
pub const CKM_PBE_MD5_CAST128_CBC = @as(c_int, 932);
pub const CKM_PBE_SHA1_CAST5_CBC = CKM_PBE_SHA1_CAST128_CBC;
pub const CKM_PBE_SHA1_CAST128_CBC = @as(c_int, 933);
pub const CKM_PBE_SHA1_RC4_128 = @as(c_int, 934);
pub const CKM_PBE_SHA1_RC4_40 = @as(c_int, 935);
pub const CKM_PBE_SHA1_DES3_EDE_CBC = @as(c_int, 936);
pub const CKM_PBE_SHA1_DES2_EDE_CBC = @as(c_int, 937);
pub const CKM_PBE_SHA1_RC2_128_CBC = @as(c_int, 938);
pub const CKM_PBE_SHA1_RC2_40_CBC = @as(c_int, 939);
pub const CKM_PKCS5_PBKD2 = @as(c_int, 944);
pub const CKM_PBA_SHA1_WITH_SHA1_HMAC = @as(c_int, 960);
pub const CKM_WTLS_PRE_MASTER_KEY_GEN = @as(c_int, 976);
pub const CKM_WTLS_MASTER_KEY_DERIVE = @as(c_int, 977);
pub const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = @as(c_int, 978);
pub const CKM_WTLS_PRF = @as(c_int, 979);
pub const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = @as(c_int, 980);
pub const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = @as(c_int, 981);
pub const CKM_TLS10_MAC_SERVER = @as(c_int, 982);
pub const CKM_TLS10_MAC_CLIENT = @as(c_int, 983);
pub const CKM_TLS12_MAC = @as(c_int, 984);
pub const CKM_TLS12_KDF = @as(c_int, 985);
pub const CKM_TLS12_MASTER_KEY_DERIVE = @as(c_int, 992);
pub const CKM_TLS12_KEY_AND_MAC_DERIVE = @as(c_int, 993);
pub const CKM_TLS12_MASTER_KEY_DERIVE_DH = @as(c_int, 994);
pub const CKM_TLS12_KEY_SAFE_DERIVE = @as(c_int, 995);
pub const CKM_TLS_MAC = @as(c_int, 996);
pub const CKM_TLS_KDF = @as(c_int, 997);
pub const CKM_KEY_WRAP_LYNKS = @as(c_int, 1024);
pub const CKM_KEY_WRAP_SET_OAEP = @as(c_int, 1025);
pub const CKM_CMS_SIG = @as(c_int, 1280);
pub const CKM_KIP_DERIVE = @as(c_int, 1296);
pub const CKM_KIP_WRAP = @as(c_int, 1297);
pub const CKM_KIP_MAC = @as(c_int, 1298);
pub const CKM_CAMELLIA_KEY_GEN = @as(c_int, 1360);
pub const CKM_CAMELLIA_ECB = @as(c_int, 1361);
pub const CKM_CAMELLIA_CBC = @as(c_int, 1362);
pub const CKM_CAMELLIA_MAC = @as(c_int, 1363);
pub const CKM_CAMELLIA_MAC_GENERAL = @as(c_int, 1364);
pub const CKM_CAMELLIA_CBC_PAD = @as(c_int, 1365);
pub const CKM_CAMELLIA_ECB_ENCRYPT_DATA = @as(c_int, 1366);
pub const CKM_CAMELLIA_CBC_ENCRYPT_DATA = @as(c_int, 1367);
pub const CKM_CAMELLIA_CTR = @as(c_int, 1368);
pub const CKM_ARIA_KEY_GEN = @as(c_int, 1376);
pub const CKM_ARIA_ECB = @as(c_int, 1377);
pub const CKM_ARIA_CBC = @as(c_int, 1378);
pub const CKM_ARIA_MAC = @as(c_int, 1379);
pub const CKM_ARIA_MAC_GENERAL = @as(c_int, 1380);
pub const CKM_ARIA_CBC_PAD = @as(c_int, 1381);
pub const CKM_ARIA_ECB_ENCRYPT_DATA = @as(c_int, 1382);
pub const CKM_ARIA_CBC_ENCRYPT_DATA = @as(c_int, 1383);
pub const CKM_SEED_KEY_GEN = @as(c_int, 1616);
pub const CKM_SEED_ECB = @as(c_int, 1617);
pub const CKM_SEED_CBC = @as(c_int, 1618);
pub const CKM_SEED_MAC = @as(c_int, 1619);
pub const CKM_SEED_MAC_GENERAL = @as(c_int, 1620);
pub const CKM_SEED_CBC_PAD = @as(c_int, 1621);
pub const CKM_SEED_ECB_ENCRYPT_DATA = @as(c_int, 1622);
pub const CKM_SEED_CBC_ENCRYPT_DATA = @as(c_int, 1623);
pub const CKM_SKIPJACK_KEY_GEN = @as(c_int, 4096);
pub const CKM_SKIPJACK_ECB64 = @as(c_int, 4097);
pub const CKM_SKIPJACK_CBC64 = @as(c_int, 4098);
pub const CKM_SKIPJACK_OFB64 = @as(c_int, 4099);
pub const CKM_SKIPJACK_CFB64 = @as(c_int, 4100);
pub const CKM_SKIPJACK_CFB32 = @as(c_int, 4101);
pub const CKM_SKIPJACK_CFB16 = @as(c_int, 4102);
pub const CKM_SKIPJACK_CFB8 = @as(c_int, 4103);
pub const CKM_SKIPJACK_WRAP = @as(c_int, 4104);
pub const CKM_SKIPJACK_PRIVATE_WRAP = @as(c_int, 4105);
pub const CKM_SKIPJACK_RELAYX = @as(c_int, 4106);
pub const CKM_KEA_KEY_PAIR_GEN = @as(c_int, 4112);
pub const CKM_KEA_KEY_DERIVE = @as(c_int, 4113);
pub const CKM_KEA_DERIVE = @as(c_int, 4114);
pub const CKM_FORTEZZA_TIMESTAMP = @as(c_int, 4128);
pub const CKM_BATON_KEY_GEN = @as(c_int, 4144);
pub const CKM_BATON_ECB128 = @as(c_int, 4145);
pub const CKM_BATON_ECB96 = @as(c_int, 4146);
pub const CKM_BATON_CBC128 = @as(c_int, 4147);
pub const CKM_BATON_COUNTER = @as(c_int, 4148);
pub const CKM_BATON_SHUFFLE = @as(c_int, 4149);
pub const CKM_BATON_WRAP = @as(c_int, 4150);
pub const CKM_ECDSA_KEY_PAIR_GEN = CKM_EC_KEY_PAIR_GEN;
pub const CKM_EC_KEY_PAIR_GEN = @as(c_int, 4160);
pub const CKM_ECDSA = @as(c_int, 4161);
pub const CKM_ECDSA_SHA1 = @as(c_int, 4162);
pub const CKM_ECDSA_SHA224 = @as(c_int, 4163);
pub const CKM_ECDSA_SHA256 = @as(c_int, 4164);
pub const CKM_ECDSA_SHA384 = @as(c_int, 4165);
pub const CKM_ECDSA_SHA512 = @as(c_int, 4166);
pub const CKM_ECDH1_DERIVE = @as(c_int, 4176);
pub const CKM_ECDH1_COFACTOR_DERIVE = @as(c_int, 4177);
pub const CKM_ECMQV_DERIVE = @as(c_int, 4178);
pub const CKM_ECDH_AES_KEY_WRAP = @as(c_int, 4179);
pub const CKM_RSA_AES_KEY_WRAP = @as(c_int, 4180);
pub const CKM_JUNIPER_KEY_GEN = @as(c_int, 4192);
pub const CKM_JUNIPER_ECB128 = @as(c_int, 4193);
pub const CKM_JUNIPER_CBC128 = @as(c_int, 4194);
pub const CKM_JUNIPER_COUNTER = @as(c_int, 4195);
pub const CKM_JUNIPER_SHUFFLE = @as(c_int, 4196);
pub const CKM_JUNIPER_WRAP = @as(c_int, 4197);
pub const CKM_FASTHASH = @as(c_int, 4208);
pub const CKM_AES_KEY_GEN = @as(c_int, 4224);
pub const CKM_AES_ECB = @as(c_int, 4225);
pub const CKM_AES_CBC = @as(c_int, 4226);
pub const CKM_AES_MAC = @as(c_int, 4227);
pub const CKM_AES_MAC_GENERAL = @as(c_int, 4228);
pub const CKM_AES_CBC_PAD = @as(c_int, 4229);
pub const CKM_AES_CTR = @as(c_int, 4230);
pub const CKM_AES_GCM = @as(c_int, 4231);
pub const CKM_AES_CCM = @as(c_int, 4232);
pub const CKM_AES_CTS = @as(c_int, 4233);
pub const CKM_AES_CMAC = @as(c_int, 4234);
pub const CKM_AES_CMAC_GENERAL = @as(c_int, 4235);
pub const CKM_AES_XCBC_MAC = @as(c_int, 4236);
pub const CKM_AES_XCBC_MAC_96 = @as(c_int, 4237);
pub const CKM_AES_GMAC = @as(c_int, 4238);
pub const CKM_BLOWFISH_KEY_GEN = @as(c_int, 4240);
pub const CKM_BLOWFISH_CBC = @as(c_int, 4241);
pub const CKM_TWOFISH_KEY_GEN = @as(c_int, 4242);
pub const CKM_TWOFISH_CBC = @as(c_int, 4243);
pub const CKM_BLOWFISH_CBC_PAD = @as(c_int, 4244);
pub const CKM_TWOFISH_CBC_PAD = @as(c_int, 4245);
pub const CKM_DES_ECB_ENCRYPT_DATA = @as(c_int, 4352);
pub const CKM_DES_CBC_ENCRYPT_DATA = @as(c_int, 4353);
pub const CKM_DES3_ECB_ENCRYPT_DATA = @as(c_int, 4354);
pub const CKM_DES3_CBC_ENCRYPT_DATA = @as(c_int, 4355);
pub const CKM_AES_ECB_ENCRYPT_DATA = @as(c_int, 4356);
pub const CKM_AES_CBC_ENCRYPT_DATA = @as(c_int, 4357);
pub const CKM_GOSTR3410_KEY_PAIR_GEN = @as(c_int, 4608);
pub const CKM_GOSTR3410 = @as(c_int, 4609);
pub const CKM_GOSTR3410_WITH_GOSTR3411 = @as(c_int, 4610);
pub const CKM_GOSTR3410_KEY_WRAP = @as(c_int, 4611);
pub const CKM_GOSTR3410_DERIVE = @as(c_int, 4612);
pub const CKM_GOSTR3411 = @as(c_int, 4624);
pub const CKM_GOSTR3411_HMAC = @as(c_int, 4625);
pub const CKM_GOST28147_KEY_GEN = @as(c_int, 4640);
pub const CKM_GOST28147_ECB = @as(c_int, 4641);
pub const CKM_GOST28147 = @as(c_int, 4642);
pub const CKM_GOST28147_MAC = @as(c_int, 4643);
pub const CKM_GOST28147_KEY_WRAP = @as(c_int, 4644);
pub const CKM_DSA_PARAMETER_GEN = @as(c_int, 8192);
pub const CKM_DH_PKCS_PARAMETER_GEN = @as(c_int, 8193);
pub const CKM_X9_42_DH_PARAMETER_GEN = @as(c_int, 8194);
pub const CKM_DSA_PROBABLISTIC_PARAMETER_GEN = @as(c_int, 8195);
pub const CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN = @as(c_int, 8196);
pub const CKM_AES_OFB = @as(c_int, 8452);
pub const CKM_AES_CFB64 = @as(c_int, 8453);
pub const CKM_AES_CFB8 = @as(c_int, 8454);
pub const CKM_AES_CFB128 = @as(c_int, 8455);
pub const CKM_AES_CFB1 = @as(c_int, 8456);
pub const CKM_AES_KEY_WRAP = @as(c_int, 8457);
pub const CKM_AES_KEY_WRAP_PAD = @as(c_int, 8458);
pub const CKM_RSA_PKCS_TPM_1_1 = @as(c_int, 16385);
pub const CKM_RSA_PKCS_OAEP_TPM_1_1 = @as(c_int, 16386);
pub const CKM_VENDOR_DEFINED = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CKF_HW = @as(c_int, 1);
pub const CKF_ENCRYPT = @as(c_int, 256);
pub const CKF_DECRYPT = @as(c_int, 512);
pub const CKF_DIGEST = @as(c_int, 1024);
pub const CKF_SIGN = @as(c_int, 2048);
pub const CKF_SIGN_RECOVER = @as(c_int, 4096);
pub const CKF_VERIFY = @as(c_int, 8192);
pub const CKF_VERIFY_RECOVER = @as(c_int, 16384);
pub const CKF_GENERATE = c.promoteIntLiteral(c_int, 32768, .decimal);
pub const CKF_GENERATE_KEY_PAIR = c.promoteIntLiteral(c_int, 65536, .decimal);
pub const CKF_WRAP = c.promoteIntLiteral(c_int, 131072, .decimal);
pub const CKF_UNWRAP = c.promoteIntLiteral(c_int, 262144, .decimal);
pub const CKF_DERIVE = c.promoteIntLiteral(c_int, 524288, .decimal);
pub const CKF_EC_F_P = c.promoteIntLiteral(c_int, 1048576, .decimal);
pub const CKF_EC_F_2M = c.promoteIntLiteral(c_int, 2097152, .decimal);
pub const CKF_EC_ECPARAMETERS = c.promoteIntLiteral(c_int, 4194304, .decimal);
pub const CKF_EC_NAMEDCURVE = c.promoteIntLiteral(c_int, 8388608, .decimal);
pub const CKF_EC_UNCOMPRESS = c.promoteIntLiteral(c_int, 16777216, .decimal);
pub const CKF_EC_COMPRESS = c.promoteIntLiteral(c_int, 33554432, .decimal);
pub const CKF_EXTENSION = c.promoteIntLiteral(c_int, 2147483648, .decimal);
pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS = @as(c_int, 1);
pub const CKF_OS_LOCKING_OK = @as(c_int, 2);
pub const CKF_DONT_BLOCK = @as(c_int, 1);
pub const CKG_MGF1_SHA1 = @as(c_int, 1);
pub const CKG_MGF1_SHA256 = @as(c_int, 2);
pub const CKG_MGF1_SHA384 = @as(c_int, 3);
pub const CKG_MGF1_SHA512 = @as(c_int, 4);
pub const CKG_MGF1_SHA224 = @as(c_int, 5);
pub const CKZ_DATA_SPECIFIED = @as(c_int, 1);
pub const CKD_NULL = @as(c_int, 1);
pub const CKD_SHA1_KDF = @as(c_int, 2);
pub const CKD_SHA1_KDF_ASN1 = @as(c_int, 3);
pub const CKD_SHA1_KDF_CONCATENATE = @as(c_int, 4);
pub const CKD_SHA224_KDF = @as(c_int, 5);
pub const CKD_SHA256_KDF = @as(c_int, 6);
pub const CKD_SHA384_KDF = @as(c_int, 7);
pub const CKD_SHA512_KDF = @as(c_int, 8);
pub const CKD_CPDIVERSIFY_KDF = @as(c_int, 9);
pub const CKP_PKCS5_PBKD2_HMAC_SHA1 = @as(c_int, 1);
pub const CKP_PKCS5_PBKD2_HMAC_GOSTR3411 = @as(c_int, 2);
pub const CKP_PKCS5_PBKD2_HMAC_SHA224 = @as(c_int, 3);
pub const CKP_PKCS5_PBKD2_HMAC_SHA256 = @as(c_int, 4);
pub const CKP_PKCS5_PBKD2_HMAC_SHA384 = @as(c_int, 5);
pub const CKP_PKCS5_PBKD2_HMAC_SHA512 = @as(c_int, 6);
pub const CKP_PKCS5_PBKD2_HMAC_SHA512_224 = @as(c_int, 7);
pub const CKP_PKCS5_PBKD2_HMAC_SHA512_256 = @as(c_int, 8);
pub const CKZ_SALT_SPECIFIED = @as(c_int, 1);
pub const CK_OTP_VALUE = @as(c_int, 0);
pub const CK_OTP_PIN = @as(c_int, 1);
pub const CK_OTP_CHALLENGE = @as(c_int, 2);
pub const CK_OTP_TIME = @as(c_int, 3);
pub const CK_OTP_COUNTER = @as(c_int, 4);
pub const CK_OTP_FLAGS = @as(c_int, 5);
pub const CK_OTP_OUTPUT_LENGTH = @as(c_int, 6);
pub const CK_OTP_OUTPUT_FORMAT = @as(c_int, 7);
pub const CKF_NEXT_OTP = @as(c_int, 1);
pub const CKF_EXCLUDE_TIME = @as(c_int, 2);
pub const CKF_EXCLUDE_COUNTER = @as(c_int, 4);
pub const CKF_EXCLUDE_CHALLENGE = @as(c_int, 8);
pub const CKF_EXCLUDE_PIN = @as(c_int, 16);
pub const CKF_USER_FRIENDLY_OTP = @as(c_int, 32);

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
