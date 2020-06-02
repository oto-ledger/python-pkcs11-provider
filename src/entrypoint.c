/**
 * PKCS#11 initialization routines.
 *
 * These are written in C so that we can initialize Python.
 */

#include <Python.h>

#include "../extern/pkcs11.h"
#include "pkcs11.h"


static CK_BBOOL did_PyInitialize = CK_FALSE;

static void ensureInit() {
  if (!Py_IsInitialized()) {
    // Add a built-in module, before Py_Initialize
    if (PyImport_AppendInittab("pkcs11", PyInit_pkcs11) == -1) {
        fprintf(stderr, "Error: could not extend in-built modules table\n");
        exit(1);
    }

    Py_Initialize();

    // Must import the module to make sure its dependencies are resolved (and also 
    // to initialize builtins such as print)
    PyObject* pmodule = PyImport_ImportModule("pkcs11");
    if (!pmodule) {
        PyErr_Print();
        fprintf(stderr, "Error: could not import module 'pkcs11'\n");
        exit(-1);
    }


    did_PyInitialize = CK_TRUE;
  }
}

CK_RV
C_Initialize(void *flags)
{
  printf("Entry: C_initialize\n");
  ensureInit();
  // Call into our Cython initialize function.
  return _C_Initialize(flags);
}


CK_RV
C_Finalize(void *flags)
{
    printf("Entry: C_Finalize\n");
    // Call into our Cython finalize function.
    CK_RV rv = _C_Finalize(flags);

    if (did_PyInitialize)
      {
        Py_Finalize();
      }

    return rv;
}


CK_RV 
C_GetFunctionList   (   CK_FUNCTION_LIST * * ppFunctionList  ) 
{
  ensureInit();
  return _C_GetFunctionList(ppFunctionList);
}