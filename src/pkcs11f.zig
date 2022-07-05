const pkcs11t = @import("pkcs11t.zig");

pub extern fn C_Initialize(pInitArgs: pkcs11t.CK_C_INITIALIZE_ARGS_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_Finalize` indicates that an application is done with the Cryptoki library.
///
/// # Function Parameters
///
/// * `pReserved`: reserved.  Should be NULL_PTR
///
pub extern fn C_Finalize(pReserved: pkcs11t.CK_VOID_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_GetInfo` returns general information about Cryptoki.
///
/// # Function Parameters
///
/// * `pInfo`: location that receives information
///
pub extern fn C_GetInfo(pInfo: pkcs11t.CK_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_GetFunctionList` returns the function list.
///
/// # Function Parameters
///
/// * `ppFunctionList`: receives pointer to function list
///
pub extern fn C_GetFunctionList(ppFunctionList: pkcs11t.CK_FUNCTION_LIST_PTR_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_GetSlotList` obtains a list of slots in the system.
///
/// # Function Parameters
///
/// * `tokenPresent`: only slots with tokens
/// * `pSlotList`: receives array of slot IDs
/// * `pulCount`: receives number of slots
///
pub extern fn C_GetSlotList(
    tokenPresent: pkcs11t.CK_BBOOL,
    pSlotList: pkcs11t.CK_SLOT_ID_PTR,
    pulCount: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_GetSlotInfo` obtains information about a particular slot in the system.
///
/// # Function Parameters
///
/// * `slotID`: the ID of the slot
/// * `pInfo`: receives the slot information
///
pub extern fn C_GetSlotInfo(slotID: pkcs11t.CK_SLOT_ID, pInfo: pkcs11t.CK_SLOT_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_GetTokenInfo` obtains information about a particular token in the system.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `pInfo`: receives the token information
///
pub extern fn C_GetTokenInfo(slotID: pkcs11t.CK_SLOT_ID, pInfo: pkcs11t.CK_TOKEN_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_GetMechanismList` obtains a list of mechanism types supported by a token.
///
/// # Function Parameters
///
/// * `slotID`: ID of token's slot
/// * `pMechanismList`: gets mech. array
/// * `pulCount`: gets # of mechs.
///
pub extern fn C_GetMechanismList(
    slotID: pkcs11t.CK_SLOT_ID,
    pMechanismList: pkcs11t.CK_MECHANISM_TYPE_PTR,
    pulCount: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_GetMechanismInfo` obtains information about a particular mechanism possibly supported by a token.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `mechType`: type of mechanism
/// * `pInfo`: receives mechanism info
///
pub extern fn C_GetMechanismInfo(
    slotID: pkcs11t.CK_SLOT_ID,
    mechType: pkcs11t.CK_MECHANISM_TYPE,
    pInfo: pkcs11t.CK_MECHANISM_INFO_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_InitToken` initializes a token.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `pPin`: the SO's initial PIN
/// * `ulPinLen`: length in bytes of the PIN
/// * `pLabel`: 32-byte token label (blank padded)
///
pub extern fn C_InitToken(
    slotID: pkcs11t.CK_SLOT_ID,
    pPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11t.CK_ULONG,
    pLabel: pkcs11t.CK_UTF8CHAR_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_InitPIN` initializes the normal user's PIN.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPin`: the normal user's PIN
/// * `ulPinLen`: length in bytes of the PIN
///
pub extern "C" fn C_InitPIN(hSession: pkcs11t.CK_SESSION_HANDLE, pPin: pkcs11t.CK_UTF8CHAR_PTR, ulPinLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `C_SetPIN` modifies the PIN of the user who is logged in.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pOldPin`: the old PIN
/// * `ulOldLen`: length of the old PIN
/// * `pNewPin`: the new PIN
/// * `ulNewLen`: length of the new PIN
///
pub extern fn C_SetPIN(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pOldPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulOldLen: pkcs11t.CK_ULONG,
    pNewPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulNewLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_OpenSession` opens a session between an application and a token.
///
/// # Function Parameters
///
/// * `slotID`: the slot's ID
/// * `flags`: from CK_SESSION_INFO
/// * `pApplication`: passed to callback
/// * `Notify`: callback function
/// * `phSession`: gets session handle
///
pub extern fn C_OpenSession(
    slotID: pkcs11t.CK_SLOT_ID,
    flags: pkcs11t.CK_FLAGS,
    pApplication: pkcs11t.CK_VOID_PTR,
    Notify: pkcs11t.CK_NOTIFY,
    phSession: pkcs11t.CK_SESSION_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_CloseSession` closes a session between an application and a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn C_CloseSession(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_CloseAllSessions` closes all sessions with a token.
///
/// # Function Parameters
///
/// * `slotID`: the token's slot
///
pub extern fn C_CloseAllSessions(slotID: pkcs11t.CK_SLOT_ID) callconv(.C) pkcs11t.CK_RV;

/// `C_GetSessionInfo` obtains information about the session.
///
/// # Function Paramters
///
/// * `hSession`: the session's handle
/// * `pInfo`: receives session info
///
pub extern fn C_GetSessionInfo(hSession: pkcs11t.CK_SESSION_HANDLE, pInfo: pkcs11t.CK_SESSION_INFO_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_GetOperationState` obtains the state of the cryptographic operation in a session.
///
/// # Function Paramters
///
/// * `hSession`: session's handle
/// * `pOperationState`: gets state
/// * `pulOperationStateLen`: gets state length
///
pub extern fn C_GetOperationState(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pOperationState: pkcs11t.CK_BYTE_PTR,
    pulOperationStateLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SetOperationState` restores the state of the cryptographic operation in a session.
///
/// # Function Paramters
///
/// * `hSession`: session's handle
/// * `pOperationState`: holds state
/// * `ulOperationStateLen`: holds state length
/// * `hEncryptionKey`: en/decryption key
/// * `hAuthenticationKey`: sign/verify key
///
pub extern fn C_SetOperationState(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pOperationState: pkcs11t.CK_BYTE_PTR,
    ulOperationStateLen: pkcs11t.CK_ULONG,
    hEncryptionKey: pkcs11t.CK_OBJECT_HANDLE,
    hAuthenticationKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_Login` logs a user into a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `userType`: the user type
/// * `pPin`: the user's PIN
/// * `ulPinLen`: the length of the PIN
///
pub extern fn C_Login(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    userType: pkcs11t.CK_USER_TYPE,
    pPin: pkcs11t.CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_Logout` logs a user out from a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
pub extern fn C_Logout(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_CreateObject` creates a new object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pTemplate`: the object's template
/// * `ulCount`: attributes in template
/// * `phObject`: gets new object's handle.
///
pub extern fn C_CreateObject(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
    phObject: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_CopyObject` copies an object, creating a new object for the copy.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pTemplate`: template for new object
/// * `ulCount`: attributes in template
/// * `phNewObject`: receives handle of copy
///
pub extern fn C_CopyObject(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
    phNewObject: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DestroyObject` destroys an object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
///
pub extern fn C_DestroyObject(hSession: pkcs11t.CK_SESSION_HANDLE, hObject: pkcs11t.CK_OBJECT_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_GetObjectSize` gets the size of an object in bytes.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pulSize`: receives size of object
///
pub extern fn C_GetObjectSize(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pulSize: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_GetAttributeValue` obtains the value of one or more object attributes.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pTemplate`: specifies attrs; gets vals
/// * `ulCount`: attributes in template
///
pub extern fn C_GetAttributeValue(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SetAttributeValue` modifies the value of one or more object attributes.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hObject`: the object's handle
/// * `pTemplate`: specifies attrs and values
/// * `ulCount`: attributes in template
///
pub extern fn C_SetAttributeValue(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    hObject: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_FindObjectsInit` initializes a search for token and session objects that match a template.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pTemplate`: attribute values to match
/// * `ulCount`: attrs in search template
///
pub extern fn C_FindObjectsInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_FindObjects` continues a search for token and session objects that match a template, obtaining additional object handles.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `phObject`: gets obj. handles
/// * `ulMaxObjectCount`: max handles to get
/// * `pulObjectCount`: actual # returned
///
pub extern fn C_FindObjects(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    phObject: pkcs11t.CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: pkcs11t.CK_ULONG,
    pulObjectCount: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_FindObjectsFinal` finishes a search for token and session objects.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn C_FindObjectsFinal(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_EncryptInit` initializes an encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the encryption mechanism
/// * `hKey`: handle of encryption key
///
pub extern fn C_EncryptInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_Encrypt` encrypts single-part data.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pData`: the plaintext data
/// * `ulDataLen`: bytes of plaintext
/// * `pEncryptedData`: gets ciphertext
/// * `pulEncryptedDataLen`: gets c-text size
///
pub extern fn C_Encrypt(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pEncryptedData: pkcs11t.CK_BYTE_PTR,
    pulEncryptedDataLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_EncryptUpdate` continues a multiple-part encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext data len
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text size
///
pub extern fn C_EncryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pPart: pkcs11t.CK_BYTE_PTR,
    ulPartLen: pkcs11t.CK_ULONG,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_EncryptFinal` finishes a multiple-part encryption operation
///
/// # Function Parameters
///
/// * `hSession`: session handle
/// * `pLastEncryptedPart` last c-text
/// * `pulLastEncryptedPartLen`: gets last size
///
pub extern fn C_EncryptFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pLastEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulLastEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DecryptInit` initializes a decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the decryption mechanism
/// * `hKey`: handle of decryption key
///
pub extern fn C_DecryptInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_Decrypt` decrypts encrypted data in a single part.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedData`: ciphertext
/// * `ulEncryptedDataLen`: ciphertext length
/// * `pData`: gets plaintext
/// * `pulDataLen`: gets p-text size
///
pub extern fn C_Decrypt(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedData: pkcs11t.CK_BYTE_PTR,
    ulEncryptedDataLen: pkcs11t.CK_ULONG,
    pData: pkcs11t.CK_BYTE_PTR,
    pulDataLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DecryptUpdate` continues a multiple-part decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: encrypted data
/// * `ulEncryptedPartLen`: input length
/// * `pPart`: gets plaintext
/// * `pulPartLen`: p-text size
///
pub extern fn C_DecryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11t.CK_ULONG,
    pPart: pkcs11t.CK_BYTE_PTR,
    pulPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DecryptFinal` finishes a multiple-part decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pLastPart`: gets plaintext
/// * `pulLastPartLen`: p-text size
///
pub extern fn C_DecryptFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pLastPart: pkcs11t.CK_BYTE_PTR,
    pulLastPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DigestInit` initializes a message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the digesting mechanism
///
pub extern fn C_DigestInit(hSession: pkcs11t.CK_SESSION_HANDLE, pMechanism: pkcs11t.CK_MECHANISM_PTR) callconv(.C) pkcs11t.CK_RV;

/// `C_Digest` digests data in a single part.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: data to be digested
/// * `ulDataLen`: bytes of data to digest
/// * `pDigest`: gets the message digest
/// * `pulDigestLen`: gets digest length
///
pub extern fn C_Digest(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pDigest: pkcs11t.CK_BYTE_PTR,
    pulDigestLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DigestUpdate` continues a multiple-part message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: data to be digested
/// * `ulPartLen`: bytes of data to be digested
///
pub extern fn C_DigestUpdate(hSession: pkcs11t.CK_SESSION_HANDLE, pPart: pkcs11t.CK_BYTE_PTR, ulPartLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `C_DigestKey` continues a multi-part message-digesting operation, by digesting the value of a secret key as part of the data already digested.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hKey`: secret key to digest
pub extern fn C_DigestKey(hSession: pkcs11t.CK_SESSION_HANDLE, hKey: pkcs11t.CK_OBJECT_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_DigestFinal` finishes a multiple-part message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pDigest`: gets the message digest
/// * `pulDigestLen`: gets byte count of digest
///
pub extern fn C_DigestFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pDigest: pkcs11t.CK_BYTE_PTR,
    pulDigestLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SignInit` initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the signature mechanism
/// * `hKey`: handle of signature key
///
pub extern fn C_SignInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_Sign` signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: the data to sign
/// * `ulDataLen`: count of bytes to sign
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub extern fn C_Sign(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pSignature: pkcs11t.CK_BYTE_PTR,
    pulSignatureLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SignUpdate` continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: the data to sign
/// * `ulPartLen`: count of bytes to sign
///
pub extern fn C_SignUpdate(hSession: pkcs11t.CK_SESSION_HANDLE, pPart: pkcs11t.CK_BYTE_PTR, ulPartLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `C_SignFinal` finishes a multiple-part signature operation, returning the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub extern fn C_SignFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pSignature: pkcs11t.CK_BYTE_PTR,
    pulSignatureLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SignRecoverInit` initializes a signature operation, where the data can be recovered from the signature.
/// `hSession`: the session's handle
/// `pMechanism`: the signature mechanism
/// `hKey`: handle of the signature key
pub extern fn C_SignRecoverInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SignRecover` signs data in a single operation, where the data can be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: the data to sign
/// * `ulDataLen`: count of bytes to sign
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub extern fn C_SignRecover(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pSignature: pkcs11t.CK_BYTE_PTR,
    pulSignatureLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_VerifyInit` initializes a verification operation, where the signature is an appendix to the data, and plaintext cannot cannot be recovered from the signature (e.g. DSA).
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the verification mechanism
/// * `hKey`: verification key
///
pub extern fn C_VerifyInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_Verify` verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: signed data
/// * `ulDataLen`: length of signed data
/// * `pSignature`: signature
/// * `ulSignatureLen`: signature length
///
pub extern fn C_Verify(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pData: pkcs11t.CK_BYTE_PTR,
    ulDataLen: pkcs11t.CK_ULONG,
    pSignature: pkcs11t.CK_BYTE_PTR,
    ulSignatureLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_VerifyUpdate` continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: signed data
/// * `ulPartLen`: length of signed data
///
pub extern fn C_VerifyUpdate(hSession: pkcs11t.CK_SESSION_HANDLE, pPart: pkcs11t.CK_BYTE_PTR, ulPartLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `C_VerifyFinal` finishes a multiple-part verification operation, checking the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: signature to verify
/// * `ulSignatureLen`: signature length
///
pub extern fn C_VerifyFinal(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pSignature: pkcs11t.CK_BYTE_PTR,
    ulSignatureLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_VerifyRecoverInit` initializes a signature verification operation, where the data is recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the verification mechanism
/// * `hKey`: verification key
///
pub extern fn C_VerifyRecoverInit(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
) callconv(.C) pkcs11t.CK_RV;

/// `C_VerifyRecover` verifies a signature in a single-part operation, where the data is recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: signature to verify
/// * `ulSignatureLen`: signature length
/// * `pData`: gets signed data
/// * `pulDataLen`: gets signed data len
///
pub extern fn C_VerifyRecover(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pSignature: pkcs11t.CK_BYTE_PTR,
    ulSignatureLen: pkcs11t.CK_ULONG,
    pData: pkcs11t.CK_BYTE_PTR,
    pulDataLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DigestEncryptUpdate` continues a multiple-part digesting and encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext length
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text length
///
pub extern fn C_DigestEncryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pPart: pkcs11t.CK_BYTE_PTR,
    ulPartLen: pkcs11t.CK_ULONG,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DecryptDigestUpdate` continues a multiple-part decryption and digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: ciphertext
/// * `ulEncryptedPartLen`: ciphertext length
/// * `pPart:`: gets plaintext
/// * `pulPartLen`: gets plaintext len
///
pub extern fn C_DecryptDigestUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11t.CK_ULONG,
    pPart: pkcs11t.CK_BYTE_PTR,
    pulPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SignEncryptUpdate` continues a multiple-part signing and encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext length
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text length
///
pub extern fn C_SignEncryptUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pPart: pkcs11t.CK_BYTE_PTR,
    ulPartLen: pkcs11t.CK_ULONG,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DecryptVerifyUpdate` continues a multiple-part decryption and verify operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: ciphertext
/// * `ulEncryptedPartLen`: ciphertext length
/// * `pPart`: gets plaintext
/// * `pulPartLen`: gets p-text length
///
pub extern fn C_DecryptVerifyUpdate(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11t.CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11t.CK_ULONG,
    pPart: pkcs11t.CK_BYTE_PTR,
    pulPartLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_GenerateKey` generates a secret key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: key generation mech.
/// * `pTemplate`: template for new key
/// * `ulCount`: # of attrs in template
/// * `phKey`: gets handle of new key
///
pub extern fn C_GenerateKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulCount: pkcs11t.CK_ULONG,
    phKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_GenerateKeyPair` generates a public-key/private-key pair, creating new key objects.
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
pub extern fn C_GenerateKeyPair(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    pPublicKeyTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: pkcs11t.CK_ULONG,
    pPrivateKeyTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: pkcs11t.CK_ULONG,
    phPublicKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
    phPrivateKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_WrapKey` wraps (i.e., encrypts) a key.
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
pub extern fn C_WrapKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hWrappingKey: pkcs11t.CK_OBJECT_HANDLE,
    hKey: pkcs11t.CK_OBJECT_HANDLE,
    pWrappedKey: pkcs11t.CK_BYTE_PTR,
    pulWrappedKeyLen: pkcs11t.CK_ULONG_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_UnwrapKey` unwraps (decrypts) a wrapped key, creating a new key object.
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
pub extern fn C_UnwrapKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hUnwrappingKey: pkcs11t.CK_OBJECT_HANDLE,
    pWrappedKey: pkcs11t.CK_BYTE_PTR,
    ulWrappedKeyLen: pkcs11t.CK_ULONG,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulAttributeCount: pkcs11t.CK_ULONG,
    phKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_DeriveKey` derives a key from a base key, creating a new key object.
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
pub extern fn C_DeriveKey(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    pMechanism: pkcs11t.CK_MECHANISM_PTR,
    hBaseKey: pkcs11t.CK_OBJECT_HANDLE,
    pTemplate: pkcs11t.CK_ATTRIBUTE_PTR,
    ulAttributeCount: pkcs11t.CK_ULONG,
    phKey: pkcs11t.CK_OBJECT_HANDLE_PTR,
) callconv(.C) pkcs11t.CK_RV;

/// `C_SeedRandom` mixes additional seed material into the token's random number generator.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSeed`: the seed material
/// * `ulSeedLen`: length of seed material
///
pub extern fn C_SeedRandom(hSession: pkcs11t.CK_SESSION_HANDLE, pSeed: pkcs11t.CK_BYTE_PTR, ulSeedLen: pkcs11t.CK_ULONG) callconv(.C) pkcs11t.CK_RV;

/// `C_GenerateRandom` generates random data.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `RandomData`: receives the random data
/// * `ulRandomLen`: # of bytes to generate
///
pub extern fn C_GenerateRandom(
    hSession: pkcs11t.CK_SESSION_HANDLE,
    RandomData: pkcs11t.CK_BYTE_PTR,
    ulRandomLen: pkcs11t.CK_ULONG,
) callconv(.C) pkcs11t.CK_RV;

/// `C_GetFunctionStatus` is a legacy function; it obtains an updated status of a function running in parallel with an application.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn C_GetFunctionStatus(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_CancelFunction` is a legacy function; it cancels a function running in parallel.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub extern fn C_CancelFunction(hSession: pkcs11t.CK_SESSION_HANDLE) callconv(.C) pkcs11t.CK_RV;

/// `C_WaitForSlotEvent` waits for a slot event (token insertion, removal, etc.) to occur.
///
/// # Function Parameters
///
/// * `flags`: blocking/nonblocking flag
/// * `pSlot`: location that receives the slot ID
/// * `pRserved`: reserved.  Should be NULL_PTR
///
pub extern fn C_WaitForSlotEvent(flags: pkcs11t.CK_FLAGS, pSlot: pkcs11t.CK_SLOT_ID_PTR, pRserved: pkcs11t.CK_VOID_PTR) callconv(.C) pkcs11t.CK_RV;
