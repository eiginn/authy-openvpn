#ifdef WIN32
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define AUTHY_VPN_CONF "authy-vpn.conf"
#pragma comment(lib, "ws2_32.lib")

#else
#define AUTHY_VPN_CONF "/etc/openvpn/authy/authy-vpn.conf"
#endif

#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <curl/curl.h>


#include "vendor/jsmn/jsmn.h"

#include "openvpn-plugin.h"
#include "authy_conf.h"
#include "authy_api.h"
#include "utils.h"
#include "logger.h"
#include "constants.h"

/*
 * This state expects the following config line
 * plugin authy-openvpn.so APIURL APIKEY PAM
 * where APIURL should be something like  https://api.authy.com/protected/json
 * APIKEY like d57d919d11e6b221c9bf6f7c882028f9
 * PAM pam
 * pam = 1;
 */

#define AUTHYID_LEN 16
#define AUTHYTOKEN_LEN 16
#define AUTHCACHE_MAX 1024

struct auth_cache {
  char authyID[AUTHYID_LEN];
  char authyToken[AUTHYTOKEN_LEN];
  time_t timestamp;
};

struct plugin_context {
  char *pszApiUrl;
  char *pszApiKey;
  int bPAM;
  int verbosity;
  struct auth_cache authCache[AUTHCACHE_MAX];
  int authCacheCount;
  long authCacheTimeout;
};



// Description
//
// Given an environmental variable name, search
// the envp array for its value, returning it
//
// Parameters
//
//   name            - Name of the enviromental
//   envp            - The environment
//
// Returns
//
// The value of the env variable or NULL otherwise
// if not found
//
/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 * From openvpn/sample/sample-plugins/defer/simple.c
 */
static char *
getEnv(const char *name, const char *envp[])
{
  if (envp)
  {
    int i;
    const int nameLength = strlen(name);
    for (i = 0; envp[i]; ++i)
    {
      if (!strncmp (envp[i], name, nameLength))
      {
        const char *cp = envp[i] + nameLength;
        if (*cp == '=')
          return (char *) cp + 1;
      }
    }
  }
  return NULL;
}



// Description
//
// Registers the functions that we want to intercept (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
// and initializes the plugin context that holds the api url, api key and if we are using PAM
//
// Parameters
//
//   type_mask            - Name of the enviromental
//   argv                 - arguments
//   envp                 - The environment
//
// Returns
//
// The handle to the plugin
//
OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask,
                       const char *argv[],
                       const char *envp[])
{
  /* Context Allocation */
  struct plugin_context *context;
  char *endptr;

  context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));

  if(NULL == context){
		trace(ERROR, __LINE__, "[Authy] Failed to allocate context\n");
    return (openvpn_plugin_handle_t)FAIL;
  }

  /* Save the verbosite level from env */
  const char *verbosity = getEnv("verb", envp);
  if (verbosity){
    context->verbosity = (int)strtol(verbosity, (char **)NULL, 10);
  }

  if(argv[1] && argv[2])
  {
    trace(DEBUG, __LINE__, "Plugin path = %s\n", argv[0]);
    trace(DEBUG, __LINE__, "Api URL = %s, api key %s\n", argv[1], argv[2]);
    context->pszApiUrl = (char *) calloc(strlen(argv[1]) + 1, sizeof(char));
    strncpy(context->pszApiUrl, argv[1], strlen(argv[1]));

    context->pszApiKey = (char *) calloc(strlen(argv[2]) + 1, sizeof(char));
    strncpy(context->pszApiKey, argv[2], strlen(argv[2]));

    context->bPAM  = 0;

  }

  if (argv[3] && strncmp(argv[3], "pam", 3) == 0){
    context->bPAM = 1;
  }

  if (argv[4]){
    errno = 0;
    context->authCacheTimeout = strtol(argv[4], &endptr, 10);

    if(errno != 0 || endptr == argv[4] || context->authCacheTimeout < 0) {
      trace(ERROR, __LINE__, "[Authy] AuthCache: incorrect AuthCache timeout value (parameter #4), AuthCache disabled.\n");
      context->authCacheTimeout = 0;
    } else if (context->authCacheTimeout > 0) {
      trace(INFO, __LINE__, "[Authy] AuthCache: AuthCache activated, timeout set to %ld seconds.\n", context->authCacheTimeout);
    }

  } else {
    // default: disable Auth Cache
    context->authCacheTimeout = 0;
  }

  /* reset auth cache */
  context->authCacheCount = 0;

  /* Set type_mask, a.k.a callbacks that we want to intercept */
  *type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

  /* Cast and return the context */
  return (openvpn_plugin_handle_t) context;

}



// Description
//
//  Goes through the response body looking for success. Else assumes failure
//
// Parameters
//
//   pszRespone           - Response body in json format
//
// Returns
//
// Standard RESULT
//
static RESULT
responseWasSuccessful(char *pszAuthyResponse)
{
  int cnt;
  jsmn_parser parser;
  jsmn_init(&parser);
  jsmntok_t tokens[20];
  jsmn_parse(&parser, pszAuthyResponse, tokens, 20);

  /* success isn't always on the same place, look until 19 because it
     shouldn't be the last one because it won't be a key */
  for (cnt = 0; cnt < 19; ++cnt)
  {
    if(strncmp(pszAuthyResponse + (tokens[cnt]).start, "success", (tokens[cnt]).end - (tokens[cnt]).start) == 0)
    {
      if(strncmp(pszAuthyResponse + (tokens[cnt+1]).start, "true", (tokens[cnt+1]).end - (tokens[cnt+1]).start) == 0){
        return OK;
      } else {
        return FAIL;
      }
    }
  }
	return FAIL;
}

//
// Find slot number in AuthCache for given Authy ID
// return index >= 0 if found
// return -1 for not existing
//
static int
findAuthCacheSlot(struct plugin_context *context, char *pszAuthyId)
{
  int i;

  for (i = 0; i < context->authCacheCount; i++) {
    if (strncmp(context->authCache[i].authyID, pszAuthyId, AUTHYID_LEN) == 0) {
      return i;
    }
  }

  return -1;
}

//
// Update or add new cache slot with Authy ID, Token and current timestamp
//
static int
updateAuthCache(struct plugin_context *context, char *pszAuthyId, char *pszToken)
{
  int cacheSlot = findAuthCacheSlot(context, pszAuthyId);

  if (-1 == cacheSlot) {
    if (context->authCacheCount >= AUTHCACHE_MAX) {
      trace(ERROR, __LINE__, "[Authy] AuthCache: max cache size of %d slots reached, cannot cache any more users.\n", AUTHCACHE_MAX);
      return FAIL;
    }

    cacheSlot = context->authCacheCount;
    context->authCacheCount++;

    trace(INFO, __LINE__, "[Authy] AuthCache: added new slot #%d for authyID=%s.\n", cacheSlot, pszAuthyId);
  }

  strncpy(context->authCache[cacheSlot].authyID, pszAuthyId, AUTHYID_LEN - 1);
  strncpy(context->authCache[cacheSlot].authyToken, pszToken, AUTHYTOKEN_LEN - 1);
  context->authCache[cacheSlot].timestamp = time(NULL);

  trace(INFO, __LINE__, "[Authy] AuthCache: updated slot #%d for authyID=%s with timestamp=%d.\n", 
    cacheSlot, context->authCache[cacheSlot].authyID, context->authCache[cacheSlot].timestamp);

  return OK;
}

//
// Verify Token and valid timestamp for given Authy ID in AuthCache
//
static int
verifyAuthCache(struct plugin_context *context, char *pszAuthyId, char *pszToken)
{
  int cacheSlot = findAuthCacheSlot(context, pszAuthyId);

  if (cacheSlot == -1) {
    return FAIL;
  }

  if (time(NULL) - context->authCache[cacheSlot].timestamp < context->authCacheTimeout &&
      strncmp(context->authCache[cacheSlot].authyToken, pszToken, AUTHYTOKEN_LEN) == 0) {
    return OK;
  }

  return FAIL;
}


// Description
//
// This is real core of the plugin
// it handles the authentication agains Authy services
// using the password field to obtain the OTP
// and as other authentication plugins it sets its authenication status
// to the control file
//
// Parameters
//
//   context           - Passed on by OpenVPN
//   argv              - Passed by OpenVPN
//   envp              - Passed by OpenVPN
// Returns
//
// OPENVPN_PLUGIN_FUNC_SUCCESS: If authentication was succesful
// OPENVPN_PLUGIN_FUNC_ERROR: If Auth was unsuccesful
//
static int
authenticate(struct plugin_context *context,
             const char *argv[],
             const char *envp[])
{
  int iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR; //auth failed

  RESULT r = FAIL;
  char *pszToken = NULL;
  char *pszAuthyResponse = NULL;
  char *pszCommonName = NULL;
  char *pszUsername = NULL;
  char *pszAuthyId = NULL;
  char *pszWantedCommonName = NULL;
  char *pszTokenStartPosition = NULL;


  trace(INFO, __LINE__, "[Authy] Authy Two-Factor Authentication started.\n");

  pszUsername    = getEnv("username", envp);
  if(!pszUsername){
    trace(ERROR, __LINE__,"[Authy] ERROR: Username is NULL. Marking Auth as failure.\n");
    iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
    goto EXIT;
   }

  r = getAuthyIdAndCommonName(&pszAuthyId, &pszWantedCommonName,AUTHY_VPN_CONF, pszUsername);
  if(FAILED(r)){
		trace(ERROR,
          __LINE__,
          "[Authy] Authentication failed. Authy ID was not found for %s and Two-Factor Authentication is required.\n",
          pszUsername);
    iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
    goto EXIT;
  }

  // If AuthyId is null but function still returned success means that username was not found
  // but the config allows username to logon without to factor auth.
  if(SUCCESS(r) && !pszAuthyId){

    // Login without two factor is only available when using pam. Else, it doesn't make sense to have two factor authentication,
    // as anyone could login by finding an unexisting username.
    if(FALSE == context->bPAM) {
      trace(INFO,
            __LINE__,
            "[Authy] Authentication failed. Username not found in authy-vpn.conf and since pam is not enabled, two factor is enforced for all users.\n");
      iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
      goto EXIT;
    }
		trace(INFO,
          __LINE__,
          "[Authy] Warning: Authentication succeeded because username %s was not found in config file and Two-Factor is not mandatory.\n",
          pszUsername);
    iAuthResult = OPENVPN_PLUGIN_FUNC_SUCCESS;
    goto EXIT;
  }

  pszCommonName =  getEnv("common_name", envp);
  if(pszWantedCommonName && FAILED(validateCommonName(pszCommonName, pszWantedCommonName)) ){
		trace(INFO,
          __LINE__,
          "[Authy] Authentication failed. CommonaName validation failed.\n");
    iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
    goto EXIT;
  }

  // From here we start authenticating the user token.
  pszToken  = getEnv("password", envp);
  if(!pszToken){
    trace(ERROR, __LINE__, "[Authy] ERROR: Token is NULL. Marking Auth as failure.\n");
    iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
    goto EXIT;
  }

  pszAuthyResponse= calloc(CURL_MAX_WRITE_SIZE + 1, sizeof(char)); //allocate memory for Authy Response
  if(!pszAuthyResponse){
    trace(ERROR, __LINE__, "[Authy] ERROR: Unable to allocate memory for curl response. Marking Auth as failure.\n");
    iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
    goto EXIT;
  }

  // Here check if the user is trying to just request a phone call or an sms token.
  if (0 == strcmp(pszToken, "sms")){

    sms(context->pszApiUrl, pszAuthyId, context->pszApiKey, pszAuthyResponse);
    iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR; //doing sms always fails authentication
    goto EXIT;
  }
  else if(0 == strcmp(pszToken, "call")){
     call(context->pszApiUrl, pszAuthyId, context->pszApiKey, pszAuthyResponse);
     iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR; //doing phone call always fails authentication
     goto EXIT;
  }

  //PAM Authentication: password is concatenated and separated by TOKEN_PASSWORD_SEPARATOR
  if(TRUE == context->bPAM)
  {
    pszTokenStartPosition = strrchr(pszToken, TOKEN_PASSWORD_SEPARATOR);
    if (NULL == pszTokenStartPosition){
      trace(ERROR, __LINE__, "[Authy] PAM being used but password was not properly concatenated. Use [PASSWORD]-[TOKEN].\n");
      iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;
      goto EXIT;
    }
		*pszTokenStartPosition = '\0'; // This 0 terminates the password so that pam gets only the password and not the token.
    pszToken = pszTokenStartPosition + 1;
  }

  if(context->authCacheTimeout > 0) {
    // Skip Authy Validation, if valid AuthCache entry is found
    r = verifyAuthCache(context, pszAuthyId, pszToken);

    if(SUCCESS(r)) {
      trace(INFO, __LINE__,"[Authy] AuthCache: Valid cached auth found for authyID=%s.\n", pszAuthyId);
      updateAuthCache(context, pszAuthyId, pszToken);
      iAuthResult = OPENVPN_PLUGIN_FUNC_SUCCESS; //Two-Factor Auth was succesful
      goto EXIT;
    }
  }

  trace(INFO, __LINE__, "[Authy] Authenticating username=%s, token=%s with AUTHY_ID=%s.\n", pszUsername, pszToken, pszAuthyId);

  r = verifyToken(context->pszApiUrl,
                  pszToken,
                  pszAuthyId,
                  context->pszApiKey,
                  pszAuthyResponse);

  if (SUCCESS(r) && SUCCESS(responseWasSuccessful(pszAuthyResponse))){
    // Update AuthCache
    if(context->authCacheTimeout > 0) {
      updateAuthCache(context, pszAuthyId, pszToken);
    }
    iAuthResult = OPENVPN_PLUGIN_FUNC_SUCCESS; //Two-Factor Auth was succesful
    goto EXIT;
  }

  iAuthResult = OPENVPN_PLUGIN_FUNC_ERROR;

EXIT:

	if(pszAuthyId) {cleanAndFree(pszAuthyId);}
  if(pszToken) { memset(pszToken, 0, (strlen(pszToken))); } // Cleanup the token. Password is left untouch.
  if(pszAuthyResponse) { cleanAndFree(pszAuthyResponse);};

  if(iAuthResult == OPENVPN_PLUGIN_FUNC_SUCCESS){
    trace(INFO, __LINE__, "[Authy] Auth finished. Result: Authy success for username %s.\n", pszUsername);
  }
  else{
    trace(INFO, __LINE__, "[Authy] Auth finished. Result: Authy failed for username %s.\n", pszUsername);
  }

  return iAuthResult;
}



// Description
//
// This is the function that is called when one of the registered functions of the vpn
// are called
//
// Parameters
//
//   pszRespone           - Response body in json format
//
// Returns
//
// Standard 0 is success, or something else otherwise.
//
OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  struct plugin_context *context = (struct plugin_context *) handle;

  if(type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY){
    return authenticate(context, argv, envp);
  }

  return OPENVPN_PLUGIN_FUNC_ERROR; //Auth FAILED
}

/*
 * Free the memory related with the context
 * This is call before openvpn stops the plugin
 */
OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
  struct plugin_context *context = (struct plugin_context *) handle;
  cleanAndFree(context->pszApiUrl);
  cleanAndFree(context->pszApiKey);
  free(context);
}
