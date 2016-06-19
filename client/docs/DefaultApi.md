# swagger_client.DefaultApi

All URIs are relative to *https://api.mikespub.net*

Method | HTTP request | Description
------------- | ------------- | -------------
[**fgcp_diskimages_get**](DefaultApi.md#fgcp_diskimages_get) | **GET** /fgcp/diskimages | 
[**fgcp_diskimages_options**](DefaultApi.md#fgcp_diskimages_options) | **OPTIONS** /fgcp/diskimages | 
[**fgcp_get**](DefaultApi.md#fgcp_get) | **GET** /fgcp | 
[**fgcp_options**](DefaultApi.md#fgcp_options) | **OPTIONS** /fgcp | 
[**fgcp_servertypes_get**](DefaultApi.md#fgcp_servertypes_get) | **GET** /fgcp/servertypes | 
[**fgcp_servertypes_options**](DefaultApi.md#fgcp_servertypes_options) | **OPTIONS** /fgcp/servertypes | 
[**fgcp_vsysdescriptors_get**](DefaultApi.md#fgcp_vsysdescriptors_get) | **GET** /fgcp/vsysdescriptors | 
[**fgcp_vsysdescriptors_options**](DefaultApi.md#fgcp_vsysdescriptors_options) | **OPTIONS** /fgcp/vsysdescriptors | 
[**fgcp_vsystems_get**](DefaultApi.md#fgcp_vsystems_get) | **GET** /fgcp/vsystems | 
[**fgcp_vsystems_options**](DefaultApi.md#fgcp_vsystems_options) | **OPTIONS** /fgcp/vsystems | 
[**fgcp_vsystems_vsys_id_get**](DefaultApi.md#fgcp_vsystems_vsys_id_get) | **GET** /fgcp/vsystems/{vsysId} | 
[**fgcp_vsystems_vsys_id_options**](DefaultApi.md#fgcp_vsystems_vsys_id_options) | **OPTIONS** /fgcp/vsystems/{vsysId} | 


# **fgcp_diskimages_get**
> list[DiskImage] fgcp_diskimages_get()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_diskimages_get()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_diskimages_get: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**list[DiskImage]**](DiskImage.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_diskimages_options**
> Empty fgcp_diskimages_options()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_diskimages_options()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_diskimages_options: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_get**
> Info fgcp_get()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_get()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_get: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Info**](Info.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_options**
> Empty fgcp_options()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_options()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_options: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_servertypes_get**
> list[ServerType] fgcp_servertypes_get()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_servertypes_get()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_servertypes_get: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**list[ServerType]**](ServerType.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_servertypes_options**
> Empty fgcp_servertypes_options()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_servertypes_options()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_servertypes_options: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_vsysdescriptors_get**
> list[VSysDescriptor] fgcp_vsysdescriptors_get()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_vsysdescriptors_get()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_vsysdescriptors_get: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**list[VSysDescriptor]**](VSysDescriptor.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_vsysdescriptors_options**
> Empty fgcp_vsysdescriptors_options()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_vsysdescriptors_options()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_vsysdescriptors_options: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_vsystems_get**
> list[VSystem] fgcp_vsystems_get()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_vsystems_get()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_vsystems_get: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**list[VSystem]**](VSystem.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_vsystems_options**
> Empty fgcp_vsystems_options()



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()

try: 
    api_response = api_instance.fgcp_vsystems_options()
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_vsystems_options: %s\n" % e
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_vsystems_vsys_id_get**
> VSystem fgcp_vsystems_vsys_id_get(vsys_id)



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()
vsys_id = 'vsys_id_example' # str | 

try: 
    api_response = api_instance.fgcp_vsystems_vsys_id_get(vsys_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_vsystems_vsys_id_get: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vsys_id** | **str**|  | 

### Return type

[**VSystem**](VSystem.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **fgcp_vsystems_vsys_id_options**
> Empty fgcp_vsystems_vsys_id_options(vsys_id)



### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.DefaultApi()
vsys_id = 'vsys_id_example' # str | 

try: 
    api_response = api_instance.fgcp_vsystems_vsys_id_options(vsys_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling DefaultApi->fgcp_vsystems_vsys_id_options: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vsys_id** | **str**|  | 

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

