const pkcs11t = @import("pkcs11t.zig");

pub extern fn CK_C_Initialize(pInitArgs: pkcs11t.CK_C_INITIALIZE_ARGS_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Finalize` indicates that an application is done with the Cryptoki library.
///
/// # Function Parameters
///
/// * `pReserved`: reserved.  Should be NULL_PTR
///
pub extern fn CK_C_Finalize(pReserved: pkcs11t.CK_VOID_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetInfo` returns general information about Cryptoki.
///
/// # Function Parameters
///
/// * `pInfo`: location that receives information
///
pub extern fn CK_C_GetInfo(pInfo: pkcs11t.CK_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetFunctionList` returns the function list.
///
/// # Function Parameters
///
/// * `ppFunctionList`: receives pointer to function list
///
pub extern fn CK_C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetSlotList` obtains a list of slots in the system.
///
/// # Function Parameters
///
/// * `tokenPresent`: only slots with tokens
/// * `pSlotList`: receives array of slot IDs
/// * `pulCount`: receives number of slots
///
pub extern fn CK_C_GetSlotList(
    tokenPresent: pkcs11t.CK_BBOOL,
    pSlotList: pkcs11t.CK_SLOT_ID_PTR,
    pulCount: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetSlotInfo` obtains information about a particular slot in the system.
///
/// # Function Parameters
///
/// * `slotID`: the ID of the slot
/// * `pInfo`: receives the slot information
///
pub extern fn CK_C_GetSlotInfo(slotID: pkcs11t.CK_SLOT_ID, pInfo: pkcs11t.CK_SLOT_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetTokenInfo` obtains information about a particular token in the system.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `pInfo`: receives the token information
///
pub extern fn CK_C_GetTokenInfo(slotID: pkcs11t.CK_SLOT_ID, pInfo: pkcs11t.CK_TOKEN_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetMechanismList` obtains a list of mechanism types supported by a token.
///
/// # Function Parameters
///
/// * `slotID`: ID of token's slot
/// * `pMechanismList`: gets mech. array
/// * `pulCount`: gets # of mechs.
///
pub extern fn CK_C_GetMechanismList(
    slotID: pkcs11t.CK_SLOT_ID,
    pMechanismList: pkcs11t.CK_MECHANISM_TYPE_PTR,
    pulCount: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetMechanismInfo` obtains information about a particular mechanism possibly supported by a token.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `mechType`: type of mechanism
/// * `pInfo`: receives mechanism info
///
pub extern fn CK_C_GetMechanismInfo(
    slotID: pkcs11t.CK_SLOT_ID,
    mechType: pkcs11t.CK_MECHANISM_TYPE,
    pInfo: pkcs11t.CK_MECHANISM_INFO_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_InitToken` initializes a token.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `pPin`: the SO's initial PIN
/// * `ulPinLen`: length in bytes of the PIN
/// * `pLabel`: 32-byte token label (blank padded)
///
pub extern fn CK_C_InitToken(
    slotID: pkcs11t.CK_SLOT_ID,
    pPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11t.CK_ULONG,
    pLabel: pkcs11t.CK_UTF8CHAR_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_InitPIN` initializes the normal user's PIN.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPin`: the normal user's PIN
/// * `ulPinLen`: length in bytes of the PIN
///
pub extern "C" fn CK_C_InitPIN(hSession: pkcs11t.CK_SESSION_HANDLE, pPin: pkcs11t.CK_UTF8CHAR_PTR, ulPinLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SetPIN` modifies the PIN of the user who is logged in.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pOldPin`: the old PIN
/// * `ulOldLen`: length of the old PIN
/// * `pNewPin`: the new PIN
/// * `ulNewLen`: length of the new PIN
///
pub extern fn CK_C_SetPIN(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pOldPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulOldLen: pkcs11t.CK_ULONG,
    pNewPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulNewLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_OpenSession` opens a session between an application and a token.
///
/// # Function Parameters
///
/// * `slotID`: the slot's ID
/// * `flags`: from CK_SESSION_INFO
/// * `pApplication`: passed to callback
/// * `Notify`: callback function
/// * `phSession`: gets session handle
///
pub extern fn CK_C_OpenSession(
    slotID: pkcs11t.CK_SLOT_ID,
    flags: pkcs11t.CK_FLAGS,
    pApplication: pkcs11t.CK_VOID_PTR,
    Notify: pkcs11t.CK_NOTIFY,
    phSession: pkcs11t.CK_SESSION_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_CloseSession` closes a session between an application and a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn CK_C_CloseSession(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_CloseAllSessions` closes all sessions with a token.
///
/// # Function Parameters
///
/// * `slotID`: the token's slot
///
pub extern fn CK_C_CloseAllSessions(slotID: pkcs11t.CK_SLOT_ID) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetSessionInfo` obtains information about the session.
///
/// # Function Paramters
///
/// * `hSession`: the session's handle
/// * `pInfo`: receives session info
///
pub extern fn CK_C_GetSessionInfo(hSession: pkcs11t.CK_SESSION_HANDLE, pInfo: pkcs11t.CK_SESSION_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetOperationState` obtains the state of the cryptographic operation in a session.
///
/// # Function Paramters
///
/// * `hSession`: session's handle
/// * `pOperationState`: gets state
/// * `pulOperationStateLen`: gets state length
///
pub extern fn CK_C_GetOperationState(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pOperationState: pkcs11t.CK_BYTE_PTR,
    pulOperationStateLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SetOperationState` restores the state of the cryptographic operation in a session.
///
/// # Function Paramters
///
/// * `hSession`: session's handle
/// * `pOperationState`: holds state
/// * `ulOperationStateLen`: holds state length
/// * `hEncryptionKey`: en/decryption key
/// * `hAuthenticationKey`: sign/verify key
///
pub extern fn CK_C_SetOperationState(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pOperationState: pkcs11t.CK_BYTE_PTR,
    ulOperationStateLen: pkcs11t.CK_ULONG,
    hEncryptionKey: pkcs11t.CK_OBJECT_HANDLE,
    hAuthenticationKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Login` logs a user into a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `userType`: the user type
/// * `pPin`: the user's PIN
/// * `ulPinLen`: the length of the PIN
///
pub extern fn CK_C_Login(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    userType: pkcs11t.CK_USER_TYPE,
    pPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Logout` logs a user out from a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
pub extern fn CK_C_Logout(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_CreateObject` creates a new object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pTemplate`: the object's template
/// * `ulCount`: attributes in template
/// * `phObject`: gets new object's handle.
///
pub extern fn CK_C_CreateObject(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
    phObject: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_CopyObject` copies an object, creating a new object for the copy.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pTemplate`: template for new object
/// * `ulCount`: attributes in template
/// * `phNewObject`: receives handle of copy
///
pub extern fn CK_C_CopyObject(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
    phNewObject: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DestroyObject` destroys an object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
///
pub extern fn CK_C_DestroyObject(hSession: pkcs11t.CK_SESSION_HANDLE, hObject: pkcs11t.CK_OBJECT_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetObjectSize` gets the size of an object in bytes.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pulSize`: receives size of object
///
pub extern fn CK_C_GetObjectSize(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pulSize: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetAttributeValue` obtains the value of one or more object attributes.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pTemplate`: specifies attrs; gets vals
/// * `ulCount`: attributes in template
///
pub extern fn CK_C_GetAttributeValue(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SetAttributeValue` modifies the value of one or more object attributes.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pTemplate`: specifies attrs and values
/// * `ulCount`: attributes in template
///
pub extern fn CK_C_SetAttributeValue(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_FindObjectsInit` initializes a search for token and session objects that match a template.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pTemplate`: attribute values to match
/// * `ulCount`: attrs in search template
///
pub extern fn CK_C_FindObjectsInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_FindObjects` continues a search for token and session objects that match a template, obtaining additional object handles.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `phObject`: gets obj. handles
/// * `ulMaxObjectCount`: max handles to get
/// * `pulObjectCount`: actual # returned
///
pub extern fn CK_C_FindObjects(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    phObject: pkcs11t.CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: pkcs11t.CK_ULONG,
    pulObjectCount: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_FindObjectsFinal` finishes a search for token and session objects.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn CK_C_FindObjectsFinal(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_EncryptInit` initializes an encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the encryption mechanism
/// * `hKey`: handle of encryption key
///
pub extern fn CK_C_EncryptInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Encrypt` encrypts single-part data.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pData`: the plaintext data
/// * `ulDataLen`: bytes of plaintext
/// * `pEncryptedData`: gets ciphertext
/// * `pulEncryptedDataLen`: gets c-text size
///
pub extern fn CK_C_Encrypt(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pEncryptedData: pkcs11t.CK_BYTE_PTR,
    pulEncryptedDataLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_EncryptUpdate` continues a multiple-part encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext data len
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text size
///
pub extern fn CK_C_EncryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pPart: pkcs11t.CK_BYTE_PTR,
    ulPartLen: pkcs11t.CK_ULONG,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_EncryptFinal` finishes a multiple-part encryption operation
///
/// # Function Parameters
///
/// * `hSession`: session handle
/// * `pLastEncryptedPart` last c-text
/// * `pulLastEncryptedPartLen`: gets last size
///
pub extern fn CK_C_EncryptFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pLastEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulLastEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DecryptInit` initializes a decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the decryption mechanism
/// * `hKey`: handle of decryption key
///
pub extern fn CK_C_DecryptInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Decrypt` decrypts encrypted data in a single part.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedData`: ciphertext
/// * `ulEncryptedDataLen`: ciphertext length
/// * `pData`: gets plaintext
/// * `pulDataLen`: gets p-text size
///
pub extern fn CK_C_Decrypt(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedData: pkcs11t.CK_BYTE_PTR,
    ulEncryptedDataLen: pkcs11t.CK_ULONG,
    pData: pkcs11t.CK_BYTE_PTR,
    pulDataLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DecryptUpdate` continues a multiple-part decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: encrypted data
/// * `ulEncryptedPartLen`: input length
/// * `pPart`: gets plaintext
/// * `pulPartLen`: p-text size
///
pub extern fn CK_C_DecryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11t.CK_ULONG,
    pPart: pkcs11t.CK_BYTE_PTR,
    pulPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DecryptFinal` finishes a multiple-part decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pLastPart`: gets plaintext
/// * `pulLastPartLen`: p-text size
///
pub extern fn CK_C_DecryptFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pLastPart: pkcs11t.CK_BYTE_PTR,
    pulLastPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DigestInit` initializes a message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the digesting mechanism
///
pub extern fn CK_C_DigestInit(hSession: pkcs11t.CK_SESSION_HANDLE, pMechanism: pkcs11t.CK_MECHANISM_PTR) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Digest` digests data in a single part.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: data to be digested
/// * `ulDataLen`: bytes of data to digest
/// * `pDigest`: gets the message digest
/// * `pulDigestLen`: gets digest length
///
pub extern fn CK_C_Digest(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pDigest: pkcs11t.CK_BYTE_PTR,
    pulDigestLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DigestUpdate` continues a multiple-part message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: data to be digested
/// * `ulPartLen`: bytes of data to be digested
///
pub extern fn CK_C_DigestUpdate(hSession: pkcs11t.CK_SESSION_HANDLE, pPart: pkcs11t.CK_BYTE_PTR, ulPartLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DigestKey` continues a multi-part message-digesting operation, by digesting the value of a secret key as part of the data already digested.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hKey`: secret key to digest
pub extern fn CK_C_DigestKey(hSession: pkcs11t.CK_SESSION_HANDLE, hKey: pkcs11t.CK_OBJECT_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DigestFinal` finishes a multiple-part message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pDigest`: gets the message digest
/// * `pulDigestLen`: gets byte count of digest
///
pub extern fn CK_C_DigestFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pDigest: pkcs11t.CK_BYTE_PTR,
    pulDigestLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SignInit` initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the signature mechanism
/// * `hKey`: handle of signature key
///
pub extern fn CK_C_SignInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Sign` signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: the data to sign
/// * `ulDataLen`: count of bytes to sign
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub extern fn CK_C_Sign(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pSignature: pkcs11t.CK_BYTE_PTR,
    pulSignatureLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SignUpdate` continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: the data to sign
/// * `ulPartLen`: count of bytes to sign
///
pub extern fn CK_C_SignUpdate(hSession: pkcs11t.CK_SESSION_HANDLE, pPart: pkcs11t.CK_BYTE_PTR, ulPartLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SignFinal` finishes a multiple-part signature operation, returning the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub extern fn CK_C_SignFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pSignature: pkcs11t.CK_BYTE_PTR,
    pulSignatureLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SignRecoverInit` initializes a signature operation, where the data can be recovered from the signature.
/// `hSession`: the session's handle
/// `pMechanism`: the signature mechanism
/// `hKey`: handle of the signature key
pub extern fn CK_C_SignRecoverInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SignRecover` signs data in a single operation, where the data can be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: the data to sign
/// * `ulDataLen`: count of bytes to sign
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub extern fn CK_C_SignRecover(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pSignature: pkcs11t.CK_BYTE_PTR,
    pulSignatureLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_VerifyInit` initializes a verification operation, where the signature is an appendix to the data, and plaintext cannot cannot be recovered from the signature (e.g. DSA).
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the verification mechanism
/// * `hKey`: verification key
///
pub extern fn CK_C_VerifyInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_Verify` verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: signed data
/// * `ulDataLen`: length of signed data
/// * `pSignature`: signature
/// * `ulSignatureLen`: signature length
///
pub extern fn CK_C_Verify(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pSignature: pkcs11t.CK_BYTE_PTR,
    ulSignatureLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_VerifyUpdate` continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: signed data
/// * `ulPartLen`: length of signed data
///
pub extern fn CK_C_VerifyUpdate(hSession: pkcs11t.CK_SESSION_HANDLE, pPart: pkcs11t.CK_BYTE_PTR, ulPartLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_VerifyFinal` finishes a multiple-part verification operation, checking the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: signature to verify
/// * `ulSignatureLen`: signature length
///
pub extern fn CK_C_VerifyFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pSignature: pkcs11t.CK_BYTE_PTR,
    ulSignatureLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_VerifyRecoverInit` initializes a signature verification operation, where the data is recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the verification mechanism
/// * `hKey`: verification key
///
pub extern fn CK_C_VerifyRecoverInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_VerifyRecover` verifies a signature in a single-part operation, where the data is recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: signature to verify
/// * `ulSignatureLen`: signature length
/// * `pData`: gets signed data
/// * `pulDataLen`: gets signed data len
///
pub extern fn CK_C_VerifyRecover(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pSignature: pkcs11t.CK_BYTE_PTR,
    ulSignatureLen: pkcs11t.CK_ULONG,
    pData: pkcs11t.CK_BYTE_PTR,
    pulDataLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DigestEncryptUpdate` continues a multiple-part digesting and encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext length
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text length
///
pub extern fn CK_C_DigestEncryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pPart: pkcs11t.CK_BYTE_PTR,
    ulPartLen: pkcs11t.CK_ULONG,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DecryptDigestUpdate` continues a multiple-part decryption and digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: ciphertext
/// * `ulEncryptedPartLen`: ciphertext length
/// * `pPart:`: gets plaintext
/// * `pulPartLen`: gets plaintext len
///
pub extern fn CK_C_DecryptDigestUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11t.CK_ULONG,
    pPart: pkcs11t.CK_BYTE_PTR,
    pulPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SignEncryptUpdate` continues a multiple-part signing and encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext length
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text length
///
pub extern fn CK_C_SignEncryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pPart: pkcs11t.CK_BYTE_PTR,
    ulPartLen: pkcs11t.CK_ULONG,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DecryptVerifyUpdate` continues a multiple-part decryption and verify operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: ciphertext
/// * `ulEncryptedPartLen`: ciphertext length
/// * `pPart`: gets plaintext
/// * `pulPartLen`: gets p-text length
///
pub extern fn CK_C_DecryptVerifyUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11t.CK_ULONG,
    pPart: pkcs11t.CK_BYTE_PTR,
    pulPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GenerateKey` generates a secret key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: key generation mech.
/// * `pTemplate`: template for new key
/// * `ulCount`: # of attrs in template
/// * `phKey`: gets handle of new key
///
pub extern fn CK_C_GenerateKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
    phKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GenerateKeyPair` generates a public-key/private-key pair, creating new key objects.
///
/// # Function Parameters
///
/// * `hSession`: session handle
/// * `pMechanism`: key-gen mech.
/// * `pPublicKeyTemplate`: template for pub. key
/// * `ulPublicKeyAttributeCount`: # pub. attrs.
/// * `pPrivateKeyTemplate`: template for priv. key
/// * `ulPrivateKeyAttributeCount`: # priv.  attrs.
/// * `phPublicKey`: gets pub. key handle
/// * `phPrivateKey`: gets priv. key handle
///
pub extern fn CK_C_GenerateKeyPair(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    pPublicKeyTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: pkcs11t.CK_ULONG,
    pPrivateKeyTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: pkcs11t.CK_ULONG,
    phPublicKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
    phPrivateKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_WrapKey` wraps (i.e., encrypts) a key.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the wrapping mechanism
/// * `hWrappingKey`: wrapping key
/// * `hKey`: key to be wrapped
/// * `pWrappedKey`: gets wrapped key
/// * `pulWrappedKeyLen`: gets wrapped key size
///
pub extern fn CK_C_WrapKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hWrappingKey: pkcs11t.CK_OBJECT_HANDLE,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
    pWrappedKey: pkcs11t.CK_BYTE_PTR,
    pulWrappedKeyLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_UnwrapKey` unwraps (decrypts) a wrapped key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pMechanism`: unwrapping mech.
/// * `hUnwrappingKey`: unwrapping key
/// * `pWrappedKey`: the wrapped key
/// * `ulWrappedKeyLen`: wrapped key len
/// * `pTemplate`: new key template
/// * `ulAttributeCount`: template length
/// * `phKey`: gets new handle
///
pub extern fn CK_C_UnwrapKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hUnwrappingKey: pkcs11t.CK_OBJECT_HANDLE,
    pWrappedKey: pkcs11t.CK_BYTE_PTR,
    ulWrappedKeyLen: pkcs11t.CK_ULONG,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulAttributeCount: pkcs11t.CK_ULONG,
    phKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_DeriveKey` derives a key from a base key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pMechanism`: key deriv. mech.
/// * `hBaseKey`: base key
/// * `pTemplate`: new key template
/// * `ulAttributeCount`: template length
/// * `phKey`: gets new handle
///
pub extern fn CK_C_DeriveKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hBaseKey: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulAttributeCount: pkcs11t.CK_ULONG,
    phKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_SeedRandom` mixes additional seed material into the token's random number generator.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSeed`: the seed material
/// * `ulSeedLen`: length of seed material
///
pub extern fn CK_C_SeedRandom(hSession: pkcs11t.CK_SESSION_HANDLE, pSeed: pkcs11t.CK_BYTE_PTR, ulSeedLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GenerateRandom` generates random data.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `RandomData`: receives the random data
/// * `ulRandomLen`: # of bytes to generate
///
pub extern fn CK_C_GenerateRandom(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    RandomData: pkcs11t.CK_BYTE_PTR,
    ulRandomLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_GetFunctionStatus` is a legacy function; it obtains an updated status of a function running in parallel with an application.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn CK_C_GetFunctionStatus(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_CancelFunction` is a legacy function; it cancels a function running in parallel.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn CK_C_CancelFunction(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `CK_C_WaitForSlotEvent` waits for a slot event (token insertion, removal, etc.) to occur.
///
/// # Function Parameters
///
/// * `flags`: blocking/nonblocking flag
/// * `pSlot`: location that receives the slot ID
/// * `pRserved`: reserved.  Should be NULL_PTR
///
pub extern fn CK_C_WaitForSlotEvent(flags: pkcs11t.CK_FLAGS, pSlot: pkcs11t.CK_SLOT_ID_PTR, pRserved: pkcs11t.CK_VOID_PTR) callconv(.C) pkcs11t.CK_RV;

pub const CK_FUNCTION_LIST_PTR_PTR = ?[*]CK_FUNCTION_LIST_PTR;
pub const CK_FUNCTION_LIST_PTR = [*]CK_FUNCTION_LIST;
pub const CK_FUNCTION_LIST = extern struct {
    version: pkcs11t.CK_VERSION,

    const C_Initialize = CK_C_Initialize;
    const C_Finalize = CK_C_Finalize;
    const C_GetInfo = CK_C_GetInfo;
    const C_GetFunctionList = CK_C_GetFunctionList;
    const C_GetSlotList = CK_C_GetSlotList;
    const C_GetSlotInfo = CK_C_GetSlotInfo;
    const C_GetTokenInfo = CK_C_GetTokenInfo;
    const C_GetMechanismList = CK_C_GetMechanismList;
    const C_GetMechanismInfo = CK_C_GetMechanismInfo;
    const C_InitToken = CK_C_InitToken;
    const C_InitPIN = CK_C_InitPIN;
    const C_SetPIN = CK_C_SetPIN;
    const C_OpenSession = CK_C_OpenSession;
    // C_CloseSession = CK_C_CloseSession,
    // C_CloseAllSessions = CK_C_CloseAllSessions,
    // C_GetSessionInfo = CK_C_GetSessionInfo,
    // C_GetOperationState = CK_C_GetOperationState,
    // C_SetOperationState = CK_C_SetOperationState,
    // C_Login = CK_C_Login,
    // C_Logout = CK_C_Logout,
    // C_CreateObject = CK_C_CreateObject,
    // C_CopyObject = CK_C_CopyObject,
    // C_DestroyObject = CK_C_DestroyObject,
    // C_GetObjectSize = CK_C_GetObjectSize,
    // C_GetAttributeValue = CK_C_GetAttributeValue,
    // C_SetAttributeValue = CK_C_SetAttributeValue,
    // C_FindObjectsInit = CK_C_FindObjectsInit,
    // C_FindObjects = CK_C_FindObjects,
    // C_FindObjectsFinal = CK_C_FindObjectsFinal,
    // C_EncryptInit = CK_C_EncryptInit,
    // C_Encrypt = CK_C_Encrypt,
    // C_EncryptUpdate = CK_C_EncryptUpdate,
    // C_EncryptFinal = CK_C_EncryptFinal,
    // C_DecryptInit = CK_C_DecryptInit,
    // C_Decrypt = CK_C_Decrypt,
    // C_DecryptUpdate = CK_C_DecryptUpdate,
    // C_DecryptFinal = CK_C_DecryptFinal,
    // C_DigestInit = CK_C_DigestInit,
    // C_Digest = CK_C_Digest,
    // C_DigestUpdate = CK_C_DigestUpdate,
    // C_DigestKey = CK_C_DigestKey,
    // C_DigestFinal = CK_C_DigestFinal,
    // C_SignInit = CK_C_SignInit,
    // C_Sign = CK_C_Sign,
    // C_SignUpdate = CK_C_SignUpdate,
    // C_SignFinal = CK_C_SignFinal,
    // C_SignRecoverInit = CK_C_SignRecoverInit,
    // C_SignRecover = CK_C_SignRecover,
    // C_VerifyInit = CK_C_VerifyInit,
    // C_Verify = CK_C_Verify,
    // C_VerifyUpdate = CK_C_VerifyUpdate,
    // C_VerifyFinal = CK_C_VerifyFinal,
    // C_VerifyRecoverInit = CK_C_VerifyRecoverInit,
    // C_VerifyRecover = CK_C_VerifyRecover,
    // C_DigestEncryptUpdate = CK_C_DigestEncryptUpdate,
    // C_DecryptDigestUpdate = CK_C_DecryptDigestUpdate,
    // C_SignEncryptUpdate = CK_C_SignEncryptUpdate,
    // C_DecryptVerifyUpdate = CK_C_DecryptVerifyUpdate,
    // C_GenerateKey = CK_C_GenerateKey,
    // C_GenerateKeyPair = CK_C_GenerateKeyPair,
    // C_WrapKey = CK_C_WrapKey,
    // C_UnwrapKey = CK_C_UnwrapKey,
    // C_DeriveKey = CK_C_DeriveKey,
    // C_SeedRandom = CK_C_SeedRandom,
    // C_GenerateRandom = CK_C_GenerateRandom,
    // C_GetFunctionStatus = CK_C_GetFunctionStatus,
    // C_CancelFunction = CK_C_CancelFunction,
    // C_WaitForSlotEvent = CK_C_WaitForSlotEvent,
};

test "Reference all the declarations" {
    @import("std").testing.refAllDecls(@This());
}
