/* Copyright (c) OASIS Open 2016-2020. All Rights Reserved.
 * Distributed under the terms of the OASIS IPR Policy,
 * [http://www.oasis-open.org/policies-guidelines/ipr], AS-IS, WITHOUT ANY
 * IMPLIED OR EXPRESS WARRANTY; there is no warranty of MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE or NONINFRINGEMENT of the rights of others.
 */
        

/* See top of pkcs11.h for information about the macros that
 * must be defined and the structure-packing conventions that
 * must be set before including this file.
 */

#ifndef _PKCS11T_H_
#define _PKCS11T_H_ 1

#define CRYPTOKI_VERSION_MAJOR          3
#define CRYPTOKI_VERSION_MINOR          0
#define CRYPTOKI_VERSION_AMENDMENT      0

#define CK_TRUE         1
#define CK_FALSE        0

#ifndef CK_DISABLE_TRUE_FALSE
#ifndef FALSE
#define FALSE CK_FALSE
#endif
#ifndef TRUE
#define TRUE CK_TRUE
#endif
#endif

/* an unsigned 8-bit value */
typedef unsigned char     CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
typedef long int          CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG          CK_FLAGS;


/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION      (~0UL)
#define CK_EFFECTIVELY_INFINITE         0UL


// typedef CK_BYTE     CK_PTR   CK_BYTE_PTR;
// typedef CK_CHAR     CK_PTR   CK_CHAR_PTR;
// typedef CK_UTF8CHAR CK_PTR   CK_UTF8CHAR_PTR;
// typedef CK_ULONG    CK_PTR   CK_ULONG_PTR;
// typedef void        CK_PTR   CK_VOID_PTR;
// 
// /* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
// typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;


/* The following value is always invalid if used as a session
 * handle or object handle
 */
#define CK_INVALID_HANDLE       0UL


typedef struct CK_VERSION {
  CK_BYTE       major;  /* integer portion of version number */
  CK_BYTE       minor;  /* 1/100ths portion of version number */
} CK_VERSION;

// typedef CK_VERSION CK_PTR CK_VERSION_PTR;


typedef struct CK_INFO {
  CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  CK_FLAGS      flags;               /* must be zero */
  CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
  CK_VERSION    libraryVersion;          /* version of library */
} CK_INFO;

// typedef CK_INFO CK_PTR    CK_INFO_PTR;


/* CK_NOTIFICATION enumerates the types of notifications that
 * Cryptoki provides to an application
 */
typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER           0UL
#define CKN_OTP_CHANGED         1UL

typedef CK_ULONG          CK_SLOT_ID;

// typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;


/* CK_SLOT_INFO provides information about a slot */
typedef struct CK_SLOT_INFO {
  CK_UTF8CHAR   slotDescription[64];  /* blank padded */
  CK_UTF8CHAR   manufacturerID[32];   /* blank padded */
  CK_FLAGS      flags;

  CK_VERSION    hardwareVersion;  /* version of hardware */
  CK_VERSION    firmwareVersion;  /* version of firmware */
} CK_SLOT_INFO;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag              Mask        Meaning
 */
#define CKF_TOKEN_PRESENT     0x00000001UL  /* a token is there */
#define CKF_REMOVABLE_DEVICE  0x00000002UL  /* removable devices*/
#define CKF_HW_SLOT           0x00000004UL  /* hardware slot */

// typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;


/* CK_TOKEN_INFO provides information about a token */
typedef struct CK_TOKEN_INFO {
  CK_UTF8CHAR   label[32];           /* blank padded */
  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  CK_UTF8CHAR   model[16];           /* blank padded */
  CK_CHAR       serialNumber[16];    /* blank padded */
  CK_FLAGS      flags;               /* see below */

  CK_ULONG      ulMaxSessionCount;     /* max open sessions */
  CK_ULONG      ulSessionCount;        /* sess. now open */
  CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
  CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
  CK_ULONG      ulMaxPinLen;           /* in bytes */
  CK_ULONG      ulMinPinLen;           /* in bytes */
  CK_ULONG      ulTotalPublicMemory;   /* in bytes */
  CK_ULONG      ulFreePublicMemory;    /* in bytes */
  CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
  CK_ULONG      ulFreePrivateMemory;   /* in bytes */
  CK_VERSION    hardwareVersion;       /* version of hardware */
  CK_VERSION    firmwareVersion;       /* version of firmware */
  CK_CHAR       utcTime[16];           /* time */
} CK_TOKEN_INFO;

/* The flags parameter is defined as follows:
 *      Bit Flag                    Mask        Meaning
 */
#define CKF_RNG                     0x00000001UL  /* has random # generator */
#define CKF_WRITE_PROTECTED         0x00000002UL  /* token is write-protected */
#define CKF_LOGIN_REQUIRED          0x00000004UL  /* user must login */
#define CKF_USER_PIN_INITIALIZED    0x00000008UL  /* normal user's PIN is set */

/* CKF_RESTORE_KEY_NOT_NEEDED.  If it is set,
 * that means that *every* time the state of cryptographic
 * operations of a session is successfully saved, all keys
 * needed to continue those operations are stored in the state
 */
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020UL

/* CKF_CLOCK_ON_TOKEN.  If it is set, that means
 * that the token has some sort of clock.  The time on that
 * clock is returned in the token info structure
 */
#define CKF_CLOCK_ON_TOKEN          0x00000040UL

/* CKF_PROTECTED_AUTHENTICATION_PATH.  If it is
 * set, that means that there is some way for the user to login
 * without sending a PIN through the Cryptoki library itself
 */
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL

/* CKF_DUAL_CRYPTO_OPERATIONS.  If it is true,
 * that means that a single session with the token can perform
 * dual simultaneous cryptographic operations (digest and
 * encrypt; decrypt and digest; sign and encrypt; and decrypt
 * and sign)
 */
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200UL

/* CKF_TOKEN_INITIALIZED. If it is true, the
 * token has been initialized using C_InitializeToken or an
 * equivalent mechanism outside the scope of PKCS #11.
 * Calling C_InitializeToken when this flag is set will cause
 * the token to be reinitialized.
 */
#define CKF_TOKEN_INITIALIZED       0x00000400UL

/* CKF_SECONDARY_AUTHENTICATION. If it is
 * true, the token supports secondary authentication for
 * private key objects.
 */
#define CKF_SECONDARY_AUTHENTICATION  0x00000800UL

/* CKF_USER_PIN_COUNT_LOW. If it is true, an
 * incorrect user login PIN has been entered at least once
 * since the last successful authentication.
 */
#define CKF_USER_PIN_COUNT_LOW       0x00010000UL

/* CKF_USER_PIN_FINAL_TRY. If it is true,
 * supplying an incorrect user PIN will it to become locked.
 */
#define CKF_USER_PIN_FINAL_TRY       0x00020000UL

/* CKF_USER_PIN_LOCKED. If it is true, the
 * user PIN has been locked. User login to the token is not
 * possible.
 */
#define CKF_USER_PIN_LOCKED          0x00040000UL

/* CKF_USER_PIN_TO_BE_CHANGED. If it is true,
 * the user PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card.
 */
#define CKF_USER_PIN_TO_BE_CHANGED   0x00080000UL

/* CKF_SO_PIN_COUNT_LOW. If it is true, an
 * incorrect SO login PIN has been entered at least once since
 * the last successful authentication.
 */
#define CKF_SO_PIN_COUNT_LOW         0x00100000UL

/* CKF_SO_PIN_FINAL_TRY. If it is true,
 * supplying an incorrect SO PIN will it to become locked.
 */
#define CKF_SO_PIN_FINAL_TRY         0x00200000UL

/* CKF_SO_PIN_LOCKED. If it is true, the SO
 * PIN has been locked. SO login to the token is not possible.
 */
#define CKF_SO_PIN_LOCKED            0x00400000UL

/* CKF_SO_PIN_TO_BE_CHANGED. If it is true,
 * the SO PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card.
 */
#define CKF_SO_PIN_TO_BE_CHANGED     0x00800000UL

#define CKF_ERROR_STATE              0x01000000UL

// typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;


/* CK_SESSION_HANDLE is a Cryptoki-assigned value that
 * identifies a session
 */
typedef CK_ULONG          CK_SESSION_HANDLE;


#define CKF_HKDF_SALT_NULL   0x00000001UL
#define CKF_HKDF_SALT_DATA   0x00000002UL
#define CKF_HKDF_SALT_KEY    0x00000004UL

#endif /* _PKCS11T_H_ */
