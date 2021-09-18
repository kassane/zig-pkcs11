pub const CK_BYTE = u8;
pub const CK_CHAR = CK_BYTE;
pub const CK_UTF8CHAR = CK_BYTE;
pub const CK_BBOOL = CK_BYTE;
pub const CK_ULONG = c_ulong;
pub const CK_LONG = c_long;
pub const CK_FLAGS = CK_ULONG;
pub const struct_CK_VERSION = extern struct {
    major: CK_BYTE,
    minor: CK_BYTE,
};
pub const CK_VERSION = struct_CK_VERSION;
pub const struct_CK_INFO = extern struct {
    cryptokiVersion: CK_VERSION,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    libraryDescription: [32]CK_UTF8CHAR,
    libraryVersion: CK_VERSION,
};
pub const CK_INFO = struct_CK_INFO;
pub const CK_NOTIFICATION = CK_ULONG;
pub const CK_SLOT_ID = CK_ULONG;
pub const struct_CK_SLOT_INFO = extern struct {
    slotDescription: [64]CK_UTF8CHAR,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
};
pub const CK_SLOT_INFO = struct_CK_SLOT_INFO;
pub const struct_CK_TOKEN_INFO = extern struct {
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
pub const CK_TOKEN_INFO = struct_CK_TOKEN_INFO;
pub const CK_SESSION_HANDLE = CK_ULONG;

pub const _PKCS11T_H_ = @as(c_int, 1);
pub const CRYPTOKI_VERSION_MAJOR = @as(c_int, 3);
pub const CRYPTOKI_VERSION_MINOR = @as(c_int, 0);
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
pub const CKF_HKDF_SALT_NULL = @as(c_ulong, 0x00000001);
pub const CKF_HKDF_SALT_DATA = @as(c_ulong, 0x00000002);
pub const CKF_HKDF_SALT_KEY = @as(c_ulong, 0x00000004);
