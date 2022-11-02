const zig_backend = @import("builtin").zig_backend;

pub const CK_BYTE = u8;
pub const CK_CHAR = CK_BYTE;
pub const CK_UTF8CHAR = CK_BYTE;
pub const CK_BBOOL = CK_BYTE;
pub const CK_ULONG = c_ulong;
pub const CK_LONG = c_long;
pub const CK_FLAGS = CK_ULONG;
pub const CK_BYTE_PTR = *CK_BYTE;
pub const CK_CHAR_PTR = *CK_CHAR;
pub const CK_UTF8CHAR_PTR = *CK_UTF8CHAR;
pub const CK_ULONG_PTR = *CK_ULONG;
pub const CK_VOID_PTR = ?*anyopaque;
pub const CK_VOID_PTR_PTR = *CK_VOID_PTR;
pub const CK_VERSION = extern struct {
    major: CK_BYTE,
    minor: CK_BYTE,
};

pub const CK_VERSION_PTR = *CK_VERSION;
pub const CK_INFO = extern struct {
    cryptokiVersion: CK_VERSION,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    libraryDescription: [32]CK_UTF8CHAR,
    libraryVersion: CK_VERSION,
};

pub const CK_INFO_PTR = *CK_INFO;
pub const CK_NOTIFICATION = CK_ULONG;
pub const CK_SLOT_ID = CK_ULONG;
pub const CK_SLOT_ID_PTR = *CK_SLOT_ID;
pub const CK_SLOT_INFO = extern struct {
    slotDescription: [64]CK_UTF8CHAR,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
};

pub const CK_SLOT_INFO_PTR = *CK_SLOT_INFO;
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
pub const CK_TOKEN_INFO_PTR = *CK_TOKEN_INFO;
pub const CK_SESSION_HANDLE = CK_ULONG;
pub const CK_SESSION_HANDLE_PTR = *CK_SESSION_HANDLE;
pub const CK_USER_TYPE = CK_ULONG;
pub const CK_STATE = CK_ULONG;
pub const CK_SESSION_INFO = extern struct {
    slotID: CK_SLOT_ID,
    state: CK_STATE,
    flags: CK_FLAGS,
    ulDeviceError: CK_ULONG,
};
pub const CK_SESSION_INFO_PTR = *CK_SESSION_INFO;
pub const CK_OBJECT_HANDLE = CK_ULONG;
pub const CK_OBJECT_HANDLE_PTR = *CK_OBJECT_HANDLE;
pub const CK_OBJECT_CLASS = CK_ULONG;
pub const CK_OBJECT_CLASS_PTR = *CK_OBJECT_CLASS;
pub const CK_HW_FEATURE_TYPE = CK_ULONG;
pub const CK_KEY_TYPE = CK_ULONG;
pub const CK_CERTIFICATE_TYPE = CK_ULONG;
pub const CK_ATTRIBUTE_TYPE = CK_ULONG;
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

pub const CK_MECHANISM_TYPE = CK_ULONG;
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

pub const CK_RV = enum(CK_ULONG) {
    CKR_OK = 0x00000000,
    CKR_CANCEL = 0x00000001,
    CKR_HOST_MEMORY = 0x00000002,
    CKR_SLOT_ID_INVALID = 0x00000003,
    CKR_GENERAL_ERROR = 0x00000005,
    CKR_FUNCTION_FAILED = 0x00000006,
    CKR_ARGUMENTS_BAD = 0x00000007,
    CKR_NO_EVENT = 0x00000008,
    CKR_NEED_TO_CREATE_THREADS = 0x00000009,
    CKR_CANT_LOCK = 0x0000000A,
    CKR_ATTRIBUTE_READ_ONLY = 0x00000010,
    CKR_ATTRIBUTE_SENSITIVE = 0x00000011,
    CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012,
    CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013,
    CKR_ACTION_PROHIBITED = 0x0000001B,
    CKR_DATA_INVALID = 0x00000020,
    CKR_DATA_LEN_RANGE = 0x00000021,
    CKR_DEVICE_ERROR = 0x00000030,
    CKR_DEVICE_MEMORY = 0x00000031,
    CKR_DEVICE_REMOVED = 0x00000032,
    CKR_ENCRYPTED_DATA_INVALID = 0x00000040,
    CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041,
    CKR_FUNCTION_CANCELED = 0x00000050,
    CKR_FUNCTION_NOT_PARALLEL = 0x00000051,
    CKR_FUNCTION_NOT_SUPPORTED = 0x00000054,
    CKR_KEY_HANDLE_INVALID = 0x00000060,
    CKR_KEY_SIZE_RANGE = 0x00000062,
    CKR_KEY_TYPE_INCONSISTENT = 0x00000063,
    CKR_KEY_NOT_NEEDED = 0x00000064,
    CKR_KEY_CHANGED = 0x00000065,
    CKR_KEY_NEEDED = 0x00000066,
    CKR_KEY_INDIGESTIBLE = 0x00000067,
    CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068,
    CKR_KEY_NOT_WRAPPABLE = 0x00000069,
    CKR_KEY_UNEXTRACTABLE = 0x0000006A,
    CKR_MECHANISM_INVALID = 0x00000070,
    CKR_MECHANISM_PARAM_INVALID = 0x00000071,
    CKR_OBJECT_HANDLE_INVALID = 0x00000082,
    CKR_OPERATION_ACTIVE = 0x00000090,
    CKR_OPERATION_NOT_INITIALIZED = 0x00000091,
    CKR_PIN_INCORRECT = 0x000000A0,
    CKR_PIN_INVALID = 0x000000A1,
    CKR_PIN_LEN_RANGE = 0x000000A2,
    CKR_PIN_EXPIRED = 0x000000A3,
    CKR_PIN_LOCKED = 0x000000A4,
    CKR_SESSION_CLOSED = 0x000000B0,
    CKR_SESSION_COUNT = 0x000000B1,
    CKR_SESSION_HANDLE_INVALID = 0x000000B3,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4,
    CKR_SESSION_READ_ONLY = 0x000000B5,
    CKR_SESSION_EXISTS = 0x000000B6,
    CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7,
    CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8,
    CKR_SIGNATURE_INVALID = 0x000000C0,
    CKR_SIGNATURE_LEN_RANGE = 0x000000C1,
    CKR_TEMPLATE_INCOMPLETE = 0x000000D0,
    CKR_TEMPLATE_INCONSISTENT = 0x000000D1,
    CKR_TOKEN_NOT_PRESENT = 0x000000E0,
    CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1,
    CKR_TOKEN_WRITE_PROTECTED = 0x000000E2,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0,
    CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2,
    CKR_USER_ALREADY_LOGGED_IN = 0x00000100,
    CKR_USER_NOT_LOGGED_IN = 0x00000101,
    CKR_USER_PIN_NOT_INITIALIZED = 0x00000102,
    CKR_USER_TYPE_INVALID = 0x00000103,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104,
    CKR_USER_TOO_MANY_TYPES = 0x00000105,
    CKR_WRAPPED_KEY_INVALID = 0x00000110,
    CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112,
    CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113,
    CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115,
    CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120,
    CKR_RANDOM_NO_RNG = 0x00000121,
    CKR_DOMAIN_PARAMS_INVALID = 0x00000130,
    CKR_CURVE_NOT_SUPPORTED = 0x00000140,
    CKR_BUFFER_TOO_SMALL = 0x00000150,
    CKR_SAVED_STATE_INVALID = 0x00000160,
    CKR_INFORMATION_SENSITIVE = 0x00000170,
    CKR_STATE_UNSAVEABLE = 0x00000180,
    CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190,
    CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191,
    CKR_MUTEX_BAD = 0x000001A0,
    CKR_MUTEX_NOT_LOCKED = 0x000001A1,
    CKR_NEW_PIN_MODE = 0x000001B0,
    CKR_NEXT_OTP = 0x000001B1,
    CKR_EXCEEDED_MAX_ITERATIONS = 0x000001B5,
    CKR_FIPS_SELF_TEST_FAILED = 0x000001B6,
    CKR_LIBRARY_LOAD_FAILED = 0x000001B7,
    CKR_PIN_TOO_WEAK = 0x000001B8,
    CKR_PUBLIC_KEY_INVALID = 0x000001B9,
    CKR_FUNCTION_REJECTED = 0x00000200,
    CKR_VENDOR_DEFINED = 0x80000000,
};

pub const CK_MECHANISM_INFO_PTR = *CK_MECHANISM_INFO;
pub const CK_NOTIFY = ?*const fn (CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_C_Initialize = ?*const fn (CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_C_Finalize = ?*const fn (CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_C_GetInfo = ?*const fn (CK_INFO_PTR) callconv(.C) CK_RV;
pub const CK_FUNCTION_LIST_PTR = *CK_FUNCTION_LIST;
pub const CK_FUNCTION_LIST_PTR_PTR = *CK_FUNCTION_LIST_PTR;
// error: dependency loop detected
// pub const CK_C_GetFunctionList = ?*const fn (CK_FUNCTION_LIST_PTR_PTR) callconv(.C) CK_RV;
pub const CK_C_GetSlotList = switch (zig_backend) {
    .stage1 => ?fn (CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) callconv(.C) CK_RV,
    else => ?*const fn (CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) callconv(.C) CK_RV,
};
pub const CK_C_GetSlotInfo = ?*const fn (CK_SLOT_ID, CK_SLOT_INFO_PTR) callconv(.C) CK_RV;
pub const CK_C_GetTokenInfo = ?*const fn (CK_SLOT_ID, CK_TOKEN_INFO_PTR) callconv(.C) CK_RV;
pub const CK_C_GetMechanismList = ?*const fn (CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_GetMechanismInfo = ?*const fn (CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR) callconv(.C) CK_RV;
pub const CK_C_InitToken = ?*const fn (CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) callconv(.C) CK_RV;
pub const CK_C_InitPIN = ?*const fn (CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_SetPIN = ?*const fn (CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_OpenSession = ?*const fn (CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_CloseSession = ?*const fn (CK_SESSION_HANDLE) callconv(.C) CK_RV;
pub const CK_C_CloseAllSessions = ?*const fn (CK_SLOT_ID) callconv(.C) CK_RV;
pub const CK_C_GetSessionInfo = ?*const fn (CK_SESSION_HANDLE, CK_SESSION_INFO_PTR) callconv(.C) CK_RV;
pub const CK_C_GetOperationState = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_SetOperationState = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_Login = ?*const fn (CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_Logout = ?*const fn (CK_SESSION_HANDLE) callconv(.C) CK_RV;
pub const CK_C_CreateObject = ?*const fn (CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_CopyObject = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_DestroyObject = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_GetObjectSize = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_GetAttributeValue = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_SetAttributeValue = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_FindObjectsInit = ?*const fn (CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_FindObjects = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_FindObjectsFinal = ?*const fn (CK_SESSION_HANDLE) callconv(.C) CK_RV;
pub const CK_C_EncryptInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_Encrypt = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_EncryptUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_EncryptFinal = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DecryptInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_Decrypt = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DecryptUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DecryptFinal = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DigestInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR) callconv(.C) CK_RV;
pub const CK_C_Digest = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DigestUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_DigestKey = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_DigestFinal = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_SignInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_Sign = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_SignUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_SignFinal = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_SignRecoverInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_SignRecover = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_VerifyInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_Verify = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_VerifyUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_VerifyFinal = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_VerifyRecoverInit = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) callconv(.C) CK_RV;
pub const CK_C_VerifyRecover = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DigestEncryptUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DecryptDigestUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_SignEncryptUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_DecryptVerifyUpdate = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_GenerateKey = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_GenerateKeyPair = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_WrapKey = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) callconv(.C) CK_RV;
pub const CK_C_UnwrapKey = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_DeriveKey = ?*const fn (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) callconv(.C) CK_RV;
pub const CK_C_SeedRandom = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_GenerateRandom = ?*const fn (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) callconv(.C) CK_RV;
pub const CK_C_GetFunctionStatus = ?*const fn (CK_SESSION_HANDLE) callconv(.C) CK_RV;
pub const CK_C_CancelFunction = ?*const fn (CK_SESSION_HANDLE) callconv(.C) CK_RV;
pub const CK_C_WaitForSlotEvent = ?*const fn (CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) callconv(.C) CK_RV;
pub const CK_FUNCTION_LIST = extern struct {
    version: CK_VERSION,
    C_Initialize: CK_C_Initialize,
    C_Finalize: CK_C_Finalize,
    C_GetInfo: CK_C_GetInfo,
    C_GetFunctionList: ?*const fn (CK_FUNCTION_LIST_PTR_PTR) callconv(.C) CK_RV,
    C_GetSlotList: CK_C_GetSlotList,
    C_GetSlotInfo: CK_C_GetSlotInfo,
    C_GetTokenInfo: CK_C_GetTokenInfo,
    C_GetMechanismList: CK_C_GetMechanismList,
    C_GetMechanismInfo: CK_C_GetMechanismInfo,
    C_InitToken: CK_C_InitToken,
    C_InitPIN: CK_C_InitPIN,
    C_SetPIN: CK_C_SetPIN,
    C_OpenSession: CK_C_OpenSession,
    C_CloseSession: CK_C_CloseSession,
    C_CloseAllSessions: CK_C_CloseAllSessions,
    C_GetSessionInfo: CK_C_GetSessionInfo,
    C_GetOperationState: CK_C_GetOperationState,
    C_SetOperationState: CK_C_SetOperationState,
    C_Login: CK_C_Login,
    C_Logout: CK_C_Logout,
    C_CreateObject: CK_C_CreateObject,
    C_CopyObject: CK_C_CopyObject,
    C_DestroyObject: CK_C_DestroyObject,
    C_GetObjectSize: CK_C_GetObjectSize,
    C_GetAttributeValue: CK_C_GetAttributeValue,
    C_SetAttributeValue: CK_C_SetAttributeValue,
    C_FindObjectsInit: CK_C_FindObjectsInit,
    C_FindObjects: CK_C_FindObjects,
    C_FindObjectsFinal: CK_C_FindObjectsFinal,
    C_EncryptInit: CK_C_EncryptInit,
    C_Encrypt: CK_C_Encrypt,
    C_EncryptUpdate: CK_C_EncryptUpdate,
    C_EncryptFinal: CK_C_EncryptFinal,
    C_DecryptInit: CK_C_DecryptInit,
    C_Decrypt: CK_C_Decrypt,
    C_DecryptUpdate: CK_C_DecryptUpdate,
    C_DecryptFinal: CK_C_DecryptFinal,
    C_DigestInit: CK_C_DigestInit,
    C_Digest: CK_C_Digest,
    C_DigestUpdate: CK_C_DigestUpdate,
    C_DigestKey: CK_C_DigestKey,
    C_DigestFinal: CK_C_DigestFinal,
    C_SignInit: CK_C_SignInit,
    C_Sign: CK_C_Sign,
    C_SignUpdate: CK_C_SignUpdate,
    C_SignFinal: CK_C_SignFinal,
    C_SignRecoverInit: CK_C_SignRecoverInit,
    C_SignRecover: CK_C_SignRecover,
    C_VerifyInit: CK_C_VerifyInit,
    C_Verify: CK_C_Verify,
    C_VerifyUpdate: CK_C_VerifyUpdate,
    C_VerifyFinal: CK_C_VerifyFinal,
    C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    C_VerifyRecover: CK_C_VerifyRecover,
    C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    C_GenerateKey: CK_C_GenerateKey,
    C_GenerateKeyPair: CK_C_GenerateKeyPair,
    C_WrapKey: CK_C_WrapKey,
    C_UnwrapKey: CK_C_UnwrapKey,
    C_DeriveKey: CK_C_DeriveKey,
    C_SeedRandom: CK_C_SeedRandom,
    C_GenerateRandom: CK_C_GenerateRandom,
    C_GetFunctionStatus: CK_C_GetFunctionStatus,
    C_CancelFunction: CK_C_CancelFunction,
    C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
};
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
pub const CK_C_INITIALIZE_ARGS_PTR = *CK_C_INITIALIZE_ARGS;
pub const CK_RSA_PKCS_MGF_TYPE = CK_ULONG;
pub const CK_RSA_PKCS_MGF_TYPE_PTR = *CK_RSA_PKCS_MGF_TYPE;
pub const CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG;
pub const CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR = *CK_RSA_PKCS_OAEP_SOURCE_TYPE;
pub const CK_RSA_PKCS_OAEP_PARAMS = extern struct {
    hashAlg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    source: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
    pSourceData: CK_VOID_PTR,
    ulSourceDataLen: CK_ULONG,
};

pub const CK_RSA_PKCS_OAEP_PARAMS_PTR = *CK_RSA_PKCS_OAEP_PARAMS;
pub const CK_RSA_PKCS_PSS_PARAMS = extern struct {
    hashAlg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    sLen: CK_ULONG,
};

pub const CK_RSA_PKCS_PSS_PARAMS_PTR = *CK_RSA_PKCS_PSS_PARAMS;
pub const CK_EC_KDF_TYPE = CK_ULONG;
pub const CK_ECDH1_DERIVE_PARAMS = extern struct {
    kdf: CK_EC_KDF_TYPE,
    ulSharedDataLen: CK_ULONG,
    pSharedData: CK_BYTE_PTR,
    ulPublicDataLen: CK_ULONG,
    pPublicData: CK_BYTE_PTR,
};

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
pub const CK_X9_42_DH_KDF_TYPE = CK_ULONG;
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
pub const CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG;
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
pub const CK_SEED_CBC_ENCRYPT_DATA_PARAMS_PTR = *CK_SEED_CBC_ENCRYPT_DATA_PARAMS;
pub extern fn C_Initialize(pInitArgs: CK_VOID_PTR) CK_RV;
pub extern fn C_Finalize(pReserved: CK_VOID_PTR) CK_RV;
pub extern fn C_GetInfo(pInfo: CK_INFO_PTR) CK_RV;
pub extern fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) CK_RV;
pub extern fn C_GetSlotList(tokenPresent: CK_BBOOL, pSlotList: CK_SLOT_ID_PTR, pulCount: CK_ULONG_PTR) CK_RV;
pub extern fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) CK_RV;
pub extern fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) CK_RV;
pub extern fn C_GetMechanismList(slotID: CK_SLOT_ID, pMechanismList: CK_MECHANISM_TYPE_PTR, pulCount: CK_ULONG_PTR) CK_RV;
pub extern fn C_GetMechanismInfo(slotID: CK_SLOT_ID, @"type": CK_MECHANISM_TYPE, pInfo: CK_MECHANISM_INFO_PTR) CK_RV;
pub extern fn C_InitToken(slotID: CK_SLOT_ID, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG, pLabel: CK_UTF8CHAR_PTR) CK_RV;
pub extern fn C_InitPIN(hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG) CK_RV;
pub extern fn C_SetPIN(hSession: CK_SESSION_HANDLE, pOldPin: CK_UTF8CHAR_PTR, ulOldLen: CK_ULONG, pNewPin: CK_UTF8CHAR_PTR, ulNewLen: CK_ULONG) CK_RV;
pub extern fn C_OpenSession(slotID: CK_SLOT_ID, flags: CK_FLAGS, pApplication: CK_VOID_PTR, Notify: CK_NOTIFY, phSession: CK_SESSION_HANDLE_PTR) CK_RV;
pub extern fn C_CloseSession(hSession: CK_SESSION_HANDLE) CK_RV;
pub extern fn C_CloseAllSessions(slotID: CK_SLOT_ID) CK_RV;
pub extern fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) CK_RV;
pub extern fn C_GetOperationState(hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, pulOperationStateLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_SetOperationState(hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, ulOperationStateLen: CK_ULONG, hEncryptionKey: CK_OBJECT_HANDLE, hAuthenticationKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_Login(hSession: CK_SESSION_HANDLE, userType: CK_USER_TYPE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG) CK_RV;
pub extern fn C_Logout(hSession: CK_SESSION_HANDLE) CK_RV;
pub extern fn C_CreateObject(hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phObject: CK_OBJECT_HANDLE_PTR) CK_RV;
pub extern fn C_CopyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phNewObject: CK_OBJECT_HANDLE_PTR) CK_RV;
pub extern fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_GetObjectSize(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pulSize: CK_ULONG_PTR) CK_RV;
pub extern fn C_GetAttributeValue(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG) CK_RV;
pub extern fn C_SetAttributeValue(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG) CK_RV;
pub extern fn C_FindObjectsInit(hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG) CK_RV;
pub extern fn C_FindObjects(hSession: CK_SESSION_HANDLE, phObject: CK_OBJECT_HANDLE_PTR, ulMaxObjectCount: CK_ULONG, pulObjectCount: CK_ULONG_PTR) CK_RV;
pub extern fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) CK_RV;
pub extern fn C_EncryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_Encrypt(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pEncryptedData: CK_BYTE_PTR, pulEncryptedDataLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_EncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_EncryptFinal(hSession: CK_SESSION_HANDLE, pLastEncryptedPart: CK_BYTE_PTR, pulLastEncryptedPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DecryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_Decrypt(hSession: CK_SESSION_HANDLE, pEncryptedData: CK_BYTE_PTR, ulEncryptedDataLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DecryptUpdate(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DecryptFinal(hSession: CK_SESSION_HANDLE, pLastPart: CK_BYTE_PTR, pulLastPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) CK_RV;
pub extern fn C_Digest(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DigestUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) CK_RV;
pub extern fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_DigestFinal(hSession: CK_SESSION_HANDLE, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_SignInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_Sign(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) CK_RV;
pub extern fn C_SignFinal(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_SignRecoverInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_SignRecover(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_VerifyInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_Verify(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG) CK_RV;
pub extern fn C_VerifyUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) CK_RV;
pub extern fn C_VerifyFinal(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG) CK_RV;
pub extern fn C_VerifyRecoverInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) CK_RV;
pub extern fn C_VerifyRecover(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DigestEncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DecryptDigestUpdate(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_SignEncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_DecryptVerifyUpdate(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_GenerateKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR) CK_RV;
pub extern fn C_GenerateKeyPair(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pPublicKeyTemplate: CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount: CK_ULONG, pPrivateKeyTemplate: CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount: CK_ULONG, phPublicKey: CK_OBJECT_HANDLE_PTR, phPrivateKey: CK_OBJECT_HANDLE_PTR) CK_RV;
pub extern fn C_WrapKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hWrappingKey: CK_OBJECT_HANDLE, hKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, pulWrappedKeyLen: CK_ULONG_PTR) CK_RV;
pub extern fn C_UnwrapKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hUnwrappingKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, ulWrappedKeyLen: CK_ULONG, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR) CK_RV;
pub extern fn C_DeriveKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hBaseKey: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR) CK_RV;
pub extern fn C_SeedRandom(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG) CK_RV;
pub extern fn C_GenerateRandom(hSession: CK_SESSION_HANDLE, RandomData: CK_BYTE_PTR, ulRandomLen: CK_ULONG) CK_RV;
pub extern fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) CK_RV;
pub extern fn C_CancelFunction(hSession: CK_SESSION_HANDLE) CK_RV;
pub extern fn C_WaitForSlotEvent(flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pRserved: CK_VOID_PTR) CK_RV;
pub const ckInfo = extern struct {
    cryptokiVersion: CK_VERSION,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    libraryDescription: [32]CK_UTF8CHAR,
    libraryVersion: CK_VERSION,
};
pub const ckInfoPtr = *ckInfo;
pub const Context = extern struct {
    handle: ?*anyopaque,
    sym: CK_FUNCTION_LIST_PTR,
};

pub fn getAttributePval(arg_a: CK_ATTRIBUTE_PTR) callconv(.C) CK_VOID_PTR {
    var a = arg_a;
    return a.*.pValue;
}

pub inline fn CK_DEFINE_FUNCTION(returnType: anytype, name: anytype) @TypeOf(returnType ++ name) {
    return returnType ++ name;
}
pub inline fn CK_DECLARE_FUNCTION(returnType: anytype, name: anytype) @TypeOf(returnType ++ name) {
    return returnType ++ name;
}
pub inline fn CK_DECLARE_FUNCTION_POINTER(returnType: anytype, name: anytype) @TypeOf(returnType(name.*)) {
    return returnType(name.*);
}
pub inline fn CK_CALLBACK_FUNCTION(returnType: anytype, name: anytype) @TypeOf(returnType(name.*)) {
    return returnType(name.*);
}

pub fn strerror(err: CK_RV) []const u8 {
    return switch (err) {
        .CKR_OK => "CKR_OK",
        .CKR_CANCEL => "CKR_CANCEL",
        .CKR_HOST_MEMORY => "CKR_HOST_MEMORY",
        .CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",
        .CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        .CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        .CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        .CKR_NO_EVENT => "CKR_NO_EVENT",
        .CKR_NEED_TO_CREATE_THREADS => "CKR_NEED_TO_CREATE_THREADS",
        .CKR_CANT_LOCK => "CKR_CANT_LOCK",
        .CKR_ATTRIBUTE_READ_ONLY => "CKR_ATTRIBUTE_READ_ONLY",
        .CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
        .CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        .CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        .CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",
        .CKR_DATA_INVALID => "CKR_DATA_INVALID",
        .CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
        .CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        .CKR_DEVICE_MEMORY => "CKR_DEVICE_MEMORY",
        .CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
        .CKR_ENCRYPTED_DATA_INVALID => "CKR_ENCRYPTED_DATA_INVALID",
        .CKR_ENCRYPTED_DATA_LEN_RANGE => "CKR_ENCRYPTED_DATA_LEN_RANGE",
        .CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        .CKR_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",
        .CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        .CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        .CKR_KEY_SIZE_RANGE => "CKR_KEY_SIZE_RANGE",
        .CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",
        .CKR_KEY_NOT_NEEDED => "CKR_KEY_NOT_NEEDED",
        .CKR_KEY_CHANGED => "CKR_KEY_CHANGED",
        .CKR_KEY_NEEDED => "CKR_KEY_NEEDED",
        .CKR_KEY_INDIGESTIBLE => "CKR_KEY_INDIGESTIBLE",
        .CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        .CKR_KEY_NOT_WRAPPABLE => "CKR_KEY_NOT_WRAPPABLE",
        .CKR_KEY_UNEXTRACTABLE => "CKR_KEY_UNEXTRACTABLE",
        .CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        .CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        .CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        .CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        .CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        .CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        .CKR_PIN_INVALID => "CKR_PIN_INVALID",
        .CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",
        .CKR_PIN_EXPIRED => "CKR_PIN_EXPIRED",
        .CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        .CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
        .CKR_SESSION_COUNT => "CKR_SESSION_COUNT",
        .CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        .CKR_SESSION_PARALLEL_NOT_SUPPORTED => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        .CKR_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
        .CKR_SESSION_EXISTS => "CKR_SESSION_EXISTS",
        .CKR_SESSION_READ_ONLY_EXISTS => "CKR_SESSION_READ_ONLY_EXISTS",
        .CKR_SESSION_READ_WRITE_SO_EXISTS => "CKR_SESSION_READ_WRITE_SO_EXISTS",
        .CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
        .CKR_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
        .CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
        .CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
        .CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        .CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
        .CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
        .CKR_UNWRAPPING_KEY_HANDLE_INVALID => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
        .CKR_UNWRAPPING_KEY_SIZE_RANGE => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
        .CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
        .CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        .CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        .CKR_USER_PIN_NOT_INITIALIZED => "CKR_USER_PIN_NOT_INITIALIZED",
        .CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",
        .CKR_USER_ANOTHER_ALREADY_LOGGED_IN => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
        .CKR_USER_TOO_MANY_TYPES => "CKR_USER_TOO_MANY_TYPES",
        .CKR_WRAPPED_KEY_INVALID => "CKR_WRAPPED_KEY_INVALID",
        .CKR_WRAPPED_KEY_LEN_RANGE => "CKR_WRAPPED_KEY_LEN_RANGE",
        .CKR_WRAPPING_KEY_HANDLE_INVALID => "CKR_WRAPPING_KEY_HANDLE_INVALID",
        .CKR_WRAPPING_KEY_SIZE_RANGE => "CKR_WRAPPING_KEY_SIZE_RANGE",
        .CKR_WRAPPING_KEY_TYPE_INCONSISTENT => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
        .CKR_RANDOM_SEED_NOT_SUPPORTED => "CKR_RANDOM_SEED_NOT_SUPPORTED",
        .CKR_RANDOM_NO_RNG => "CKR_RANDOM_NO_RNG",
        .CKR_DOMAIN_PARAMS_INVALID => "CKR_DOMAIN_PARAMS_INVALID",
        .CKR_CURVE_NOT_SUPPORTED => "CKR_CURVE_NOT_SUPPORTED",
        .CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        .CKR_SAVED_STATE_INVALID => "CKR_SAVED_STATE_INVALID",
        .CKR_INFORMATION_SENSITIVE => "CKR_INFORMATION_SENSITIVE",
        .CKR_STATE_UNSAVEABLE => "CKR_STATE_UNSAVEABLE",
        .CKR_CRYPTOKI_NOT_INITIALIZED => "CKR_CRYPTOKI_NOT_INITIALIZED",
        .CKR_CRYPTOKI_ALREADY_INITIALIZED => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        .CKR_MUTEX_BAD => "CKR_MUTEX_BAD",
        .CKR_MUTEX_NOT_LOCKED => "CKR_MUTEX_NOT_LOCKED",
        .CKR_NEW_PIN_MODE => "CKR_NEW_PIN_MODE",
        .CKR_NEXT_OTP => "CKR_NEXT_OTP",
        .CKR_EXCEEDED_MAX_ITERATIONS => "CKR_EXCEEDED_MAX_ITERATIONS",
        .CKR_FIPS_SELF_TEST_FAILED => "CKR_FIPS_SELF_TEST_FAILED",
        .CKR_LIBRARY_LOAD_FAILED => "CKR_LIBRARY_LOAD_FAILED",
        .CKR_PIN_TOO_WEAK => "CKR_PIN_TOO_WEAK",
        .CKR_PUBLIC_KEY_INVALID => "CKR_PUBLIC_KEY_INVALID",
        .CKR_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
        .CKR_VENDOR_DEFINED => "CKR_VENDOR_DEFINED",
        else => "unknown",
    };
}
