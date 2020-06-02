from __future__ import (absolute_import, unicode_literals,
                        print_function, division)

import logging

from libc.string cimport strncpy
from .types cimport *


LOGGER = logging.getLogger(__name__)

cdef CK_FUNCTION_LIST* functionList

cdef extern CK_RV C_Initialize (void*)
cdef extern CK_RV C_Finalize (void*)
cdef extern CK_RV C_GetFunctionList (CK_FUNCTION_LIST * *)

cdef public CK_RV _C_GetFunctionList   (   CK_FUNCTION_LIST * * ppFunctionList  ):
  global functionList
  try:
    print("C_GetFunctionList")
    if functionList == NULL:
      functionList = <CK_FUNCTION_LIST*>malloc(sizeof(CK_FUNCTION_LIST))
      functionList.version.major = 2
      functionList.version.minor = 40
      functionList.C_Initialize = &C_Initialize
      functionList.C_Finalize = &C_Finalize
      functionList.C_GetInfo = &C_GetInfo
      functionList.C_GetFunctionList = &C_GetFunctionList
      functionList.C_GetSlotList = &C_GetSlotList
      functionList.C_GetSlotInfo = &C_GetSlotInfo
      functionList.C_GetTokenInfo = &C_GetTokenInfo
      functionList.C_GetMechanismList = &C_GetMechanismList
      functionList.C_GetMechanismInfo = &C_GetMechanismInfo
      # functionList.C_InitToken = &C_InitToken
      # functionList.C_InitPIN = &C_InitPIN
      # functionList.C_SetPIN = &C_SetPIN
      functionList.C_OpenSession = &C_OpenSession
      functionList.C_CloseSession = &C_CloseSession
      # functionList.C_CloseAllSessions = &C_CloseAllSessions
      # functionList.C_GetSessionInfo = &C_GetSessionInfo
      # functionList.C_GetOperationState = &C_GetOperationState
      # functionList.C_SetOperationState = &C_SetOperationState
      functionList.C_Login = &C_Login
      functionList.C_Logout = &C_Logout
      functionList.C_CreateObject = &C_CreateObject
      functionList.C_CopyObject = &C_CopyObject
      functionList.C_DestroyObject = &C_DestroyObject
      # functionList.C_GetObjectSize = &C_GetObjectSize
      functionList.C_GetAttributeValue = &C_GetAttributeValue
      functionList.C_SetAttributeValue = &C_SetAttributeValue
      functionList.C_FindObjectsInit = &C_FindObjectsInit
      functionList.C_FindObjects = &C_FindObjects
      functionList.C_FindObjectsFinal = &C_FindObjectsFinal
      functionList.C_EncryptInit = &C_EncryptInit
      functionList.C_Encrypt = &C_Encrypt
      functionList.C_EncryptUpdate = &C_EncryptUpdate
      functionList.C_EncryptFinal = &C_EncryptFinal
      functionList.C_DecryptInit = &C_DecryptInit
      functionList.C_Decrypt = &C_Decrypt
      functionList.C_DecryptUpdate = &C_DecryptUpdate
      functionList.C_DecryptFinal = &C_DecryptFinal
      functionList.C_DigestInit = &C_DigestInit
      functionList.C_Digest = &C_Digest
      functionList.C_DigestUpdate = &C_DigestUpdate
      functionList.C_DigestKey = &C_DigestKey
      functionList.C_DigestFinal = &C_DigestFinal
      functionList.C_SignInit = &C_SignInit
      functionList.C_Sign = &C_Sign
      functionList.C_SignUpdate = &C_SignUpdate
      functionList.C_SignFinal = &C_SignFinal
      # functionList.C_SignRecoverInit = &C_SignRecoverInit
      # functionList.C_SignRecover = &C_SignRecover
      functionList.C_VerifyInit = &C_VerifyInit
      functionList.C_Verify = &C_Verify
      functionList.C_VerifyUpdate = &C_VerifyUpdate
      functionList.C_VerifyFinal = &C_VerifyFinal
      # functionList.C_VerifyRecoverInit = &C_VerifyRecoverInit
      # functionList.C_VerifyRecover = &C_VerifyRecover
      # functionList.C_DigestEncryptUpdate = &C_DigestEncryptUpdate
      # functionList.C_DecryptDigestUpdate = &C_DecryptDigestUpdate
      # functionList.C_SignEncryptUpdate = &C_SignEncryptUpdate
      # functionList.C_DecryptVerifyUpdate = &C_DecryptVerifyUpdate
      functionList.C_GenerateKey = &C_GenerateKey
      functionList.C_GenerateKeyPair = &C_GenerateKeyPair
      functionList.C_WrapKey = &C_WrapKey
      functionList.C_UnwrapKey = &C_UnwrapKey
      functionList.C_DeriveKey = &C_DeriveKey
      functionList.C_SeedRandom = &C_SeedRandom
      functionList.C_GenerateRandom = &C_GenerateRandom
      # functionList.C_GetFunctionStatus = &C_GetFunctionStatus
      # functionList.C_CancelFunction = &C_CancelFunction
      # functionList.C_WaitForSlotEvent = &C_WaitForSlotEvent

    ppFunctionList[0] = functionList
  except:
    print("Unhandled exception")
    return CKR_FUNCTION_FAILED

cdef public CK_RV _C_Initialize(void *flags):
    try:
        print("C_Initialize")
    except:
        LOGGER.exception("Unhandled exception")
        return CKR_FUNCTION_FAILED


cdef public CK_RV _C_Finalize(void *flags):
    try:
        print("C_Finalize")
    except:
        LOGGER.exception("Unhandled exception")
        return CKR_FUNCTION_FAILED


cdef public CK_RV C_GetInfo(CK_INFO *info):
    try:
        info.cryptokiVersion.major = 2
        info.cryptokiVersion.minor = 4

        strncpy(<char *> &info.manufacturerID[0],
                "python-pkcs11-provider"
                .ljust(sizeof(info.manufacturerID))
                .encode('utf-8'),
                sizeof(info.manufacturerID))

        info.flags = 0

        strncpy(<char *> &info.libraryDescription[0],
                "PKCS #11 provider for Python"
                .ljust(sizeof(info.libraryDescription))
                .encode('utf-8'),
                sizeof(info.libraryDescription))

        info.libraryVersion.major = 0
        info.libraryVersion.minor = 1
    except:
        LOGGER.exception("Unhandled exception")
        return CKR_FUNCTION_FAILED


cdef public CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                                CK_SLOT_ID *slots,
                                CK_ULONG *count):
    try:
        if slots == NULL:
            count[0] = 1

        else:
            assert count[0] == 1

            slots[0] = 1234
    except:
        LOGGER.exception("Unhandled exception")
        return CKR_FUNCTION_FAILED

# Slot Methods
cdef public CK_RV C_GetSlotInfo(CK_SLOT_ID slot,
                                CK_SLOT_INFO *info):
    try:
        assert slot == 1234

        strncpy(<char *> &info.slotDescription[0],
                "Slot 1234"
                .ljust(sizeof(info.slotDescription))
                .encode('utf-8'),
                sizeof(info.slotDescription))

        strncpy(<char *> &info.manufacturerID[0],
                "boo"
                .ljust(sizeof(info.manufacturerID))
                .encode('utf-8'),
                sizeof(info.manufacturerID))

        info.flags = 0

        info.hardwareVersion.major = 0
        info.hardwareVersion.minor = 1

        info.firmwareVersion.major = 0
        info.firmwareVersion.minor = 1
    except:
        LOGGER.exception("Unhandled exception")
        return CKR_FUNCTION_FAILED


cdef public CK_RV C_GetTokenInfo(CK_SLOT_ID slot,
                                 CK_TOKEN_INFO *info):
    pass


cdef public CK_RV C_GetMechanismList(CK_SLOT_ID slot,
                                     CK_MECHANISM_TYPE *mechanismList,
                                     CK_ULONG *count):
    pass


cdef public CK_RV C_GetMechanismInfo(CK_SLOT_ID slot,
                                     CK_MECHANISM_TYPE mechanism,
                                     CK_MECHANISM_INFO *info):
    pass


cdef public CK_RV C_OpenSession(CK_SLOT_ID slot,
                                CK_FLAGS flags,
                                void *application,
                                CK_RV (* notify)(CK_SESSION_HANDLE, CK_NOTIFICATION, void *),
                                CK_SESSION_HANDLE *handle):
    pass


# Session Methods
cdef public CK_RV C_Login(CK_SESSION_HANDLE session,
                          CK_USER_TYPE userType,
                          CK_UTF8CHAR *pin,
                          CK_ULONG pinLen):
    pass


cdef public CK_RV C_Logout(CK_SESSION_HANDLE session):
    pass


cdef public CK_RV C_CloseSession(CK_SESSION_HANDLE session):
    pass


cdef public CK_RV C_GenerateKey(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_ATTRIBUTE *template,
                                CK_ULONG count,
                                CK_OBJECT_HANDLE *key):
    pass


cdef public CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session,
                                    CK_MECHANISM *mechanism,
                                    CK_ATTRIBUTE *public_template,
                                    CK_ULONG public_count,
                                    CK_ATTRIBUTE *private_template,
                                    CK_ULONG private_count,
                                    CK_OBJECT_HANDLE *public_key,
                                    CK_OBJECT_HANDLE *private_key):
    pass


cdef public CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session,
                                    CK_ATTRIBUTE *template,
                                    CK_ULONG count):
    pass


cdef public CK_RV C_FindObjects(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE *objects,
                                CK_ULONG objectsMax,
                                CK_ULONG *objectsLength):
    pass


cdef public CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session):
    pass


cdef public CK_RV C_SeedRandom(CK_SESSION_HANDLE session,
                               CK_BYTE *seed,
                               CK_ULONG length):
    pass


cdef public CK_RV C_GenerateRandom(CK_SESSION_HANDLE session,
                                   CK_BYTE *random,
                                   CK_ULONG length):
    pass


cdef public CK_RV C_DigestInit(CK_SESSION_HANDLE session,
                               CK_MECHANISM *mechanism):
    pass


cdef public CK_RV C_Digest(CK_SESSION_HANDLE session,
                           CK_BYTE *data,
                           CK_ULONG data_len,
                           CK_BYTE *digest,
                           CK_ULONG *digest_len):
    pass


cdef public CK_RV C_DigestUpdate(CK_SESSION_HANDLE session,
                                 CK_BYTE *data,
                                 CK_ULONG data_len):
    pass


cdef public CK_RV C_DigestFinal(CK_SESSION_HANDLE session,
                                CK_BYTE *digest,
                                CK_ULONG *digest_len):
    pass


cdef public CK_RV C_DigestKey(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE key):
    pass


# Object Methods
cdef public CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE key,
                                      CK_ATTRIBUTE *template,
                                      CK_ULONG count):
    pass


cdef public CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE key,
                                      CK_ATTRIBUTE *template,
                                      CK_ULONG count):
    pass


cdef public CK_RV C_CreateObject(CK_SESSION_HANDLE session,
                                 CK_ATTRIBUTE *template,
                                 CK_ULONG count,
                                 CK_OBJECT_HANDLE *key):
    pass


cdef public CK_RV C_CopyObject(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE key,
                               CK_ATTRIBUTE *template,
                               CK_ULONG count,
                               CK_OBJECT_HANDLE *new_key):
    pass


cdef public CK_RV C_DestroyObject(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key):
    pass


## Encrypt
cdef public CK_RV C_EncryptInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key):
    pass


cdef public CK_RV C_Encrypt(CK_SESSION_HANDLE session,
                            CK_BYTE *plaintext,
                            CK_ULONG plaintext_len,
                            CK_BYTE *ciphertext,
                            CK_ULONG *ciphertext_len):
    pass


cdef public CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE *part_in,
                                  CK_ULONG part_in_len,
                                  CK_BYTE *part_out,
                                  CK_ULONG *part_out_len):
    pass


cdef public CK_RV C_EncryptFinal(CK_SESSION_HANDLE session,
                                 CK_BYTE *part_out,
                                 CK_ULONG *part_out_len):
    pass

## Decrypt
cdef public CK_RV C_DecryptInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key):
    pass


cdef public CK_RV C_Decrypt(CK_SESSION_HANDLE session,
                            CK_BYTE *ciphertext,
                            CK_ULONG ciphertext_len,
                            CK_BYTE *plaintext,
                            CK_ULONG *plaintext_len):
    pass


cdef public CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE *part_in,
                                  CK_ULONG part_in_len,
                                  CK_BYTE *part_out,
                                  CK_ULONG *part_out_len):
    pass


cdef public CK_RV C_DecryptFinal(CK_SESSION_HANDLE session,
                                 CK_BYTE *part_out,
                                 CK_ULONG *part_out_len):
    pass


## Sign
cdef public CK_RV C_SignInit(CK_SESSION_HANDLE session,
                             CK_MECHANISM *mechanism,
                             CK_OBJECT_HANDLE key):
    pass


cdef public CK_RV C_Sign(CK_SESSION_HANDLE session,
                         CK_BYTE *text,
                         CK_ULONG text_len,
                         CK_BYTE *signature,
                         CK_ULONG *sig_len):
    pass


cdef public CK_RV C_SignUpdate(CK_SESSION_HANDLE session,
                               CK_BYTE *part,
                               CK_ULONG part_len):
    pass


cdef public CK_RV C_SignFinal(CK_SESSION_HANDLE session,
                              CK_BYTE *signature,
                              CK_ULONG *sig_len):
    pass


## Verify
cdef public CK_RV C_VerifyInit(CK_SESSION_HANDLE session,
                               CK_MECHANISM *mechanism,
                               CK_OBJECT_HANDLE key):
    pass


cdef public CK_RV C_Verify(CK_SESSION_HANDLE session,
                           CK_BYTE *text,
                           CK_ULONG text_len,
                           CK_BYTE *signature,
                           CK_ULONG sig_len):
    pass


cdef public CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session,
                                 CK_BYTE *text,
                                 CK_ULONG text_len):
    pass


cdef public CK_RV C_VerifyFinal(CK_SESSION_HANDLE session,
                                CK_BYTE *signature,
                                CK_ULONG sig_len):
    pass


## Derive
cdef public CK_RV C_DeriveKey(CK_SESSION_HANDLE session,
                              CK_MECHANISM *mechanism,
                              CK_OBJECT_HANDLE src_key,
                              CK_ATTRIBUTE *template,
                              CK_ULONG count,
                              CK_OBJECT_HANDLE *new_key):
    pass


## Wrap
cdef public CK_RV C_WrapKey(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE wrapping_key,
                            CK_OBJECT_HANDLE key_to_wrap,
                            CK_BYTE *wrapped_key,
                            CK_ULONG *wrapped_key_len):
    pass


## Unwrap
cdef public CK_RV C_UnwrapKey(CK_SESSION_HANDLE session,
                              CK_MECHANISM *mechanism,
                              CK_OBJECT_HANDLE unwrapping_key,
                              CK_BYTE *wrapped_key,
                              CK_ULONG wrapped_key_len,
                              CK_ATTRIBUTE *attrs,
                              CK_ULONG attr_len,
                              CK_OBJECT_HANDLE *unwrapped_key):
    pass
