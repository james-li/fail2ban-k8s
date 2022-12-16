from __future__ import print_function
import time
import kubernetes.client
from kubernetes.client.rest import ApiException
from pprint import pprint

configuration = kubernetes.client.Configuration()
# Configure API key authorization: BearerToken
configuration.api_key[
    'authorization'] = 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkktMGtxbTV3dGZwSXVBUTNYdXc5dkpUZUZrRGQ5QkRHYmszMXFiRHVpbzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tN3YyMnAiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImEwYWY4MTY2LWVhOWYtNDAwNy1hZTM0LTAwNzQ0ZDkxYzlmNCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.il1So0nXwIfGVtmuFiaNHgXR8gJcDVB9KvcTmtmonysct9W6pFYBJGg5s16JbC6M-As6TU2wAheRAAWUPIiQLkOv5QArLOQdnVzM0gN1YxI3oEQRWoekfeSfDzLBit8A6GSxO1T0Qu6R9_jHPgEwEpJlT789oM5CcaOUx2NflGp-dz1jDMk_V6HVBg33sJSGGNIZG59zgWMf93orsGLHPwuepf-sUAouuUK3_SIUtlrw9W_Ve44_ojk7lEdnAmxYTk74RtqXx1xPnfQUUgCXaee7LrG-xHEwrfvbKw928TVy3SO08xXNqQr1S1em418IJaeOj7RCc3dsKhBCKsLVOg'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
#configuration.api_key_prefix['authorization'] = 'Bearer'

# Defining host is optional and default to http://localhost
configuration.host = "https://localhost:6443"

configuration.verify_ssl = False
configuration.debug = True

# Enter a context with an instance of the API kubernetes.client
with kubernetes.client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = kubernetes.client.NetworkingV1Api(api_client)
    namespace = 'test'  # str | object name and auth scope, such as for teams and projects

pprint(api_instance.list_ingress_for_all_namespaces())
body = kubernetes.client.V1NetworkPolicy()  # V1NetworkPolicy |
pretty = 'pretty_example'  # str | If 'true', then the output is pretty printed. (optional)
dry_run = 'dry_run_example'  # str | When present, indicates that modifications should not be persisted. An invalid or unrecognized dryRun directive will result in an error response and no further processing of the request. Valid values are: - All: all dry run stages will be processed (optional)
field_manager = 'field_manager_example'  # str | fieldManager is a name associated with the actor or entity that is making these changes. The value must be less than or 128 characters long, and only contain printable characters, as defined by https://golang.org/pkg/unicode/#IsPrint. (optional)
field_validation = 'field_validation_example'  # str | fieldValidation instructs the server on how to handle objects in the request (POST/PUT/PATCH) containing unknown or duplicate fields, provided that the `ServerSideFieldValidation` feature gate is also enabled. Valid values are: - Ignore: This will ignore any unknown fields that are silently dropped from the object, and will ignore all but the last duplicate field that the decoder encounters. This is the default behavior prior to v1.23 and is the default behavior when the `ServerSideFieldValidation` feature gate is disabled. - Warn: This will send a warning via the standard warning response header for each unknown field that is dropped from the object, and for each duplicate field that is encountered. The request will still succeed if there are no other errors, and will only persist the last of any duplicate fields. This is the default when the `ServerSideFieldValidation` feature gate is enabled. - Strict: This will fail the request with a BadRequest error if any unknown fields would be dropped from the object, or if any duplicate fields are present. The error returned from the server will contain all unknown and duplicate fields encountered. (optional)

try:
    api_response = api_instance.create_namespaced_network_policy(namespace, body, pretty=pretty, dry_run=dry_run,
                                                                 field_manager=field_manager,
                                                                 field_validation=field_validation)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling NetworkingV1Api->create_namespaced_network_policy: %s\n" % e)
