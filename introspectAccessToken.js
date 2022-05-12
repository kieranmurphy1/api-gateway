var fs = require('fs');
//const jwt = require('jsonwebtoken');
var privateKEY = fs.readFileSync('/etc/nginx/private.key', 'utf8');
var publicKEY = fs.readFileSync('/etc/nginx/public.key', 'utf8');

//var MyTokeFile = "/etc/nginx/conf.d/njs/mip/mytoken.dat";
var MyTokeFile = "/tmp/mytoken.dat";
//--------------------------------------------------------
//function getFunctionName() {
//    return getFuncName.caller.name
//}
//--------------------------------------------------------
function writeToken(r, t) {
    //console.log('Testing function writeToken....');
    // The token is accessed from a JavaScript variable assigned in the nginx.conf file using js_var directive
    r.log('testing writeToken().....');
    var t = "123";
    var file = fs.writeFileSync(MyTokeFile, r.variables.token_test);
    r.return(200, "created token file: " + MyTokeFile);
}
//--------------------------------------------------------
function readToken(r) {
    try {
        fs.accessSync(MyTokeFile, fs.constants.R_OK);
        //console.log('Testing function readToken....');
        r.log('readToken: Has READ access : ' + MyTokeFile);
    } catch (e) {
        r.log('readToken: No READ access : ' + MyTokeFile);
        return ("");  // Return empty string if file cannot be read.
    }

    r.log("readToken:" + MyTokeFile)
    var file = fs.readFileSync(MyTokeFile);
    var token = file.toString();
    var tokenJson = JSON.parse(token);
    r.return(200, tokenJson.username);
}
//--------------------------------------------------------
// Validate a signed JWT from IDP using the OAuth keys in the secret file.
// The JWT claims are auotmatically available as NGINX global variables.
// The JWT token part is sent to the IDP for real time expiry check.
function validateAccessToken(r) {
    r.log("validateAccessToken(): JWT Claim user_name = " + r.variables.jwt_keycloak_user_name);
    r.log("validateAccessToken(): JWT Claim unique_name = " + r.variables.jwt_mip_unique_name);
    r.log("validateAccessToken(): JWT Claim sAMAccountName = " + r.variables.jwt_mip_sAMAccountName);
    r.log("validateAccessToken(): JWT Claim employeeid = " + r.variables.jwt_mip_employeeid);
    r.log("validateAccessToken(): JWT Claim given_name = " + r.variables.jwt_mip_given_name);
    r.log("validateAccessToken(): Authorization Header = " + r.headersIn.authorization);
    r.log("validateAccessToken(): REMOTE_ADDR = " + r.remoteAddress);
    if (r.variables.validateTokenFlag == "true") {
        if (r.headersIn.authorization && r.headersIn.authorization.length > 7 && r.headersIn.authorization.charAt(6) == " ") {  // check for Bearer followed by a space.
            r.log("validateAccessToken(): r.variables.validateTokenFlag = " + r.variables.validateTokenFlag);
            var token;
            var parts = r.headersIn.authorization.split(' ');
            //r.log("validateAccessToken(): JWT Claim user_name = " + r.variables.jwt_keycloak_user_name);
            if (parts.length === 2) {
                var scheme = parts[0];
                var credentials = parts[1];            
                if (/^Bearer$/i.test(scheme)) {
                    token = credentials;
                    r.headersOut.tokenOAuth = credentials;
                    //  r.return(200,token);
                    r.log("validateAccessToken(): NJS subrequest calling IDP URL: _oauth2_send_request");
                    r.log("validateAccessToken(): NJS subrequest body = " + token);
                    //r.return(200);
                    r.subrequest("/_oauth2_send_request",
                        {
                            method: 'POST',
                            body: token
                        },
                        function (reply) {
                            if (reply.status == 200) {
                                r.variables.token_cache = reply.responseBody; // Create entry in token cache
                                tokenResult(r); // Current response now in key-value store so use cache for validation 
                            } else {
                                r.log("validateAccessToken(): Error in response " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                                r.return(reply.status, "validateAccessToken(): Error in response " + reply.uri + "\n");
                                //r.return(401); // Unexpected response, return 'auth required'
                            }
                        }
                    ); // end of r.subrequest
                } else {
                    r.return(401, "validateAccessToken(): Authorization header missing Bearer label");
                    r.log("validateAccessToken(): 401 Error - Authorization header missing Bearer label");
                }
            } else {
                r.return(401, "validateAccessToken(): Authorization header does not have 2 parts separated by a single space.\n");
                r.log("validateAccessToken(): 401 Error - Auth0rization header does not have 2 parts separated by a single space. r.headersIn.authorization = " + r.headersIn.authorization);
            }
        } else {
            r.log("validateAccessTokenCache(): 401 Error - Authorization header missing or invalid string.");
            r.return(401, "validateAccessTokenCache(): Authorization header missing or invalid string.\n");
        }   // end of authentication header test block
    }
    else {
        r.log("validateAccessToken(): r.variables.validateTokenFlag = " + r.variables.validateTokenFlag);
        r.return(200, "r.variables.validateTokenFlag = " + r.variables.validateTokenFlag);

    }
}
//--------------------------------------------------------
// The OAuth validation cache uses the request authorization header as the index-value.
// Validate a signed JWT from IDP using the OAuth keys in the secret file.
// The JWT claims are auotmatically available as NGINX global variables.
// The JWT token part is sent to the IDP for real time expiry check.
// Call tokenResult() which reads the validation status and then creates the maximoapikey.
function validateAccessTokenCache(r) {
    //var validateTokenFlag = "false";    // If true then validate token using the call to IDP.
    var validateTokenFlag = r.variables.validateTokenFlag;    // If NGINX NJS variable true then validate token using the call to IDP.
    r.log("validateAccessTokenCache(): JWT Claim user_name = " + r.variables.jwt_keycloak_user_name);
    r.log("validateAccessTokenCache(): JWT Claim unique_name = " + r.variables.jwt_mip_unique_name);
    r.log("validateAccessTokenCache(): JWT Claim sAMAccountName = " + r.variables.jwt_mip_sAMAccountName);
    r.log("validateAccessTokenCache(): JWT Claim employeeid = " + r.variables.jwt_mip_employeeid);
    r.log("validateAccessTokenCache(): JWT Claim given_name = " + r.variables.jwt_mip_given_name);
    r.log("validateAccessTokenCache(): Authorization Header = " + r.headersIn.authorization);
    r.log("validateAccessTokenCache(): REMOTE_ADDR = " + r.remoteAddress);        
    if (validateTokenFlag == "true") {
        if (r.headersIn.authorization && r.headersIn.authorization.length > 7 && r.headersIn.authorization.charAt(6) == " ") {  // check for Bearer followed by a space.
            var token;
            var parts = r.headersIn.authorization.split(' ');
            r.log("validateAccessTokenCache(): validateTokenFlag = " + validateTokenFlag);
            r.log("validateAccessTokenCache(): test if authorization header contains Bearer label and JWT");
            if (parts.length == 2) {
                var scheme = parts[0];
                var credentials = parts[1];
                if (/^Bearer$/i.test(scheme)) {
                    token = credentials;               // this JWT variable will be used in the subrequest body.
                    r.headersOut.tokenOAuth = credentials;                    
                    if (r.variables.token_cache && r.variables.use_jwt_token_cache == "true") {
                        r.log("validateAccessTokenCache(): NJS calling Auth token cache +++++");
                        try {
                            r.log("validateAccessTokenCache(): JWT token found in cache, calling tokenResult().....");
                            tokenResult(r); // Previous "true" response in key-value store so use cache for validation
                        } catch (error) {
                            r.log("validateAccessTokenCache(): Error in response from function tokenResult() - " + error);
                            r.return(596, "validateAccessTokenCache(): Error in response from function tokenResult().\n");
                            throw new Error("validateAccessTokenCache(): Error in response from function tokenResult(). MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", error =  " + error); // Custom code error, stop NJS processing.
                        }                        
                    } else {
                        r.log("validateAccessTokenCache(): JWT cache EMPTY or DISABLED, NJS subrequest calling IDP URL to validate JWT: _oauth2_send_request");
                        r.log("validateAccessTokenCache():/_oauth2_send_request - NJS subrequest body = " + token);
                        r.subrequest("/_oauth2_send_request",
                            {
                                method: 'POST',
                                body: token
                            },
                            function (reply) {
                                if (reply.status == 200) {                                    
                                    var response;
                                    try {
                                        response = JSON.parse(reply.responseBody);
                                        r.log("validateAccessTokenCache():/_oauth2_send_request - parse JSON response OK");
                                    } catch(error) {
                                        r.log("validateAccessTokenCache():/_oauth2_send_request - JSON Parse response error = " + error);                                        
                                        reply.status = 596;
                                        r.return(reply.status, error + "\n" + "validateAccessTokenCache():/_oauth2_send_request reply.responseBody = " + reply.responseBody); // Error, return reply JSON string.                                      
                                        throw new Error("validateAccessTokenCache():/_oauth2_send_request - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error); // Custom code error, stop NJS processing.
                                    }
                                    if (response.active == true) {
                                        r.log("validateAccessTokenCache(): JWT 200 response validation = true " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                                        r.variables.token_cache = reply.responseBody; // If JWT validation  == true, create entry in token cache                                    
                                        r.log("validateAccessTokenCache(): Added JWT to cache: token_cache =  " + r.variables.token_cache);
                                        try {
                                            r.log("validateAccessTokenCache(): JWT token added to cache, calling tokenResult().....");
                                            tokenResult(r); // Current response now in key-value store so use cache for validation, if true call createapikeyCache().
                                        } catch (error) {
                                            r.log("validateAccessTokenCache(): Error in response from function tokenResult() - " + error);
                                            r.return(596, "validateAccessTokenCache(): Error in response from function tokenResult().\n");
                                            throw new Error("validateAccessTokenCache(): Error in response from function tokenResult(). MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", error =  " + error); // Custom code error, stop NJS processing.
                                        }                                            
                                    } else {
                                        r.log("validateAccessTokenCache(): JWT 200 RESPONSE validation = false " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                                        r.return(401, "validateAccessTokenCache(): JWT 200 RESPONSE validation = false.\n");
                                    }

                                } else {
                                    r.log("validateAccessTokenCache(): Error in subrequest response " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                                    r.return(reply.status, "validateAccessTokenCache(): Error in response body = \n" + reply.responseBody); 
                                }
                            }
                        ); // end of r.subrequest
                    }
                } else {
                    r.log("validateAccessTokenCache(): 401 Error - Authorization header missing Bearer label. r.headersIn.authorization = " + r.headersIn.authorization);
                    r.return(401, "validateAccessTokenCache(): Authorization header missing Bearer label");
                }
            } else {
                r.log("validateAccessTokenCache(): 401 Error - Auth0rization header does not have 2 parts separated by a single space. r.headersIn.authorization = " + r.headersIn.authorization);
                r.return(401, "validateAccessTokenCache(): Authorization header does not have 2 parts separated by a single space.\n");
            }
        } else {
            r.log("validateAccessTokenCache(): 401 Error - Authorization header missing or invalid string.");
            r.return(401, "validateAccessTokenCache(): Authorization header missing or invalid string.\n");
        }   // end of authentication header test block
    } else {
        r.log("validateAccessTokenCache(): skip IDP token validation - validateTokenFlag = " + validateTokenFlag);
        var tokenTrueTest = "{\"active\": true}";
        r.variables.token_cache = tokenTrueTest; // Create test-true entry in token cache        
        r.log("validateAccessTokenCache(): skip IDP token validation - static tokenTrueTest = " + tokenTrueTest);        
        try {
            r.log("validateAccessTokenCache(): JWT token added to cache, calling tokenResult().....");
            tokenResult(r); // Current response now in key-value store so use cache for validation, if true call createapikeyCache().
        } catch (error) {
            r.log("validateAccessTokenCache(): Error in response from function tokenResult() - " + error);
            r.return(500, "validateAccessTokenCache(): Error in response from function tokenResult().\n");
            throw new Error("validateAccessTokenCache(): Error in response from function tokenResult(). MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", error =  " + error); // Custom code error, stop NJS processing.
        }         
    }   // end of validateTokenFlag test block
}
//--------------------------------------------------------
function tokenResult(r) {
    // Parse the token validation response from the IDP server.
    // If valid then check the Maximo API Key Cache for Maximo API Key
    var response = JSON.parse(r.variables.token_cache);
    r.log("tokenResult(): IDP OAuth JWT validation response - active = " + response.active);
    if (response.active == true) {
        try {
            r.log("tokenResult(): JWT token is active, calling createapikeyCache().....");            
            createapikeyCache(r);  // This is the expected flow, create Maximo API Key.
            //throw new Error("tokenResult():TEST Error Handling: MAXIMO-USER-ID =  " + r.headersIn['MAXIMO-USER-ID']);            
        } catch (error) {
            r.log("tokenResult(): Error in response from function createapikeyCache() - " + error);
            throw new Error("tokenResult(): Error in response from function createapikeyCache() - " + error);
        }
    } else {
        r.log("tokenResult(): IDP OAuth JWT validation response test failed - token validation response = " + r.variables.token_cache);
        r.return(401);  // Token is invalid, return forbidden code Unauthorized.
    }
}

//--------------------------------------------------------
// The Maximo apikey cache uses the request authorization header as the index-value.
function createapikeyCache(r) {
    var use_maximo_apikeys_cache = r.variables.use_maximo_apikeys_cache;    // Use Maximp apikey cache if true.
    r.log("createapikeyCache(): JWT Claim user_name = " + r.variables.jwt_keycloak_user_name);   // This is the preferred JWT property for Maximo UserId.
    r.log("createapikeyCache(): MIP Header - MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);  // Temporary Header for Maximo UserId until Azure JWT Claim is assigned.
    r.log("createapikeyCache(): test if Maximo API Key Cache contains user token authentication key");
    if (r.variables.maximo_apikeys_cache && use_maximo_apikeys_cache == "true") {
        r.log("createapikeyCache(): NJS calling Maximo API Key CACHE +++++ ");
        // This try/catch is not really necessary as the function parseApiKey() does not throw custom exceptions.
        try {
            r.log("createapikeyCache(): Maximo API Key found in cache, calling parseApikey().....");                            
            parseApikey(r); // Previous response in API key-value store so use cache as input for validation.
        } catch (error) {
            r.log("createapikeyCache(): Error in response from function parseApikey() - " + error);
            r.return(500, "createapikeyCache(): Error in response from function parseApikey().\n");            
        }  
    } else {
        if (use_maximo_apikeys_cache != "true") {
            r.log("createapikeyCache(): API Key cache DISABLED - calling function createapikeySync() to generate Maximo API Key");
        } else {
            r.log("createapikeyCache(): NO API Key cache entry found - calling function createapikeySync() to generate Maximo API Key");
        }
        r.log("createapikeyCache(): API Cache disabled or NO API Key cache entry - calling function createapikeySync() to generate Maximo API Key");
        //createapikeyAsync(r);
        //parseApikey(r);
        try {            
            createapikeySync(r);
            //throw new Error("createapikeyCache(): Test Error Handling in response from function createapikeySync().");
            r.log("createapikeyCache(): createapikeySync() in progress - creation of APIKEY for USER: " + r.headersIn['MAXIMO-USER-ID']);
        } catch (error) {
            r.log("createapikeyCache(): Error in response from function createapikeySync() - " + error);
            r.return(596, "createapikeyCache(): Error in response from function createapikeySync().\n");
        }
    }
}
//--------------------------------------------------------
function parseApikey(r) {
    // Parse the API Key JSON object and return the API key in a response header.
    // No try/catch block as all the operations are primitives.
    var response = JSON.parse(r.variables.maximo_apikeys_cache);
    r.log("parseApiKey(): Maximo API Keys response - payload = " + r.variables.maximo_apikeys_cache);
    r.log("parseApikey(): Maximo API Keys response - apikey = " + response.apikey);
    if (response.apikey.length > 0) {
        r.body = response;
        r.headersOut.maximoapikey = response.apikey;
        r.log("parseApikey(): Assigned Maximo API Key to response header: maximoapikey. Return to caller: NGINX location /_oauth2_token_cache_validation");
        r.return(200, "Maximo API Key Server response: " + r.variables.maximo_apikeys_cache);  // API Key is present, return success code
    } else {
        r.return(401);  // API Key not found, return forbidden code for Unauthorized.
    }
}
//--------------------------------------------------------
// The Maximo apikey cache uses the request header MAXIMO-USER-ID as the index-value.
// This function deletes any existing apikey and creates a new apikey (getmaximoapikey + deletemaximoapikey + njs_createmaximopaikey_admin).
function createapikeyAsync(r) {
    r.variables.maximoapikeyref = "";
    var deleteCommitDelayMillisec = 5000; // variable for delay timer in case the /deletemaximoapikey operation is slow to commit.
    r.log("createapikeyAsync(): JWT Claim user_name = " + r.variables.jwt_keycloak_user_name);
    r.log("createapikeyAsync(): MIP Header - MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);  // Temporary Header for Maximo UserId until Azure JWT Claim is assigned.
    r.log("createapikeyAsync(): Test if Maximo API Key Table contains key for specified user - calling /getmaximoapikey.");
    r.subrequest("/getmaximoapikey",
        {
            method: 'GET',
        },
        function (reply) {
            if (reply.status == 200) {
                var response_getmaximoapikey;
                try {
                    response_getmaximoapikey = JSON.parse(reply.responseBody);
                    r.log("createapikeyAsync():/getmaximoapikey - parse JSON response OK");
                } catch(error) {
                    r.log("createapikeyAsync():/getmaximoapikey - JSON Parse response error = " + error);
                    reply.status = 596;                   
                    r.return(reply.status, error + "\n" + "createapikeyAsync():/getmaximoapikey reply.responseBody = " + reply.responseBody); // Error, return reply JSON string.
                    throw new Error("createapikeyAsync():/getmaximoapikey - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error); // Custom code error, stop NJS processing.
                }
                r.log("createapikeyAsync(): r.headersOut.SetCookie = " + r.headersOut.SetCookie);  // Check if WQebSphere is creating cookie for client browser.      
                if (response_getmaximoapikey.member.length > 0) {
                    r.log("createapikeyAsync(): MAXIMO USER APIKEYS FOUND - response.member.length = " + response_getmaximoapikey.member.length);
                    r.log("createapikeyAsync(): Existing Maximo API Key href = " + response_getmaximoapikey.member[0].href);
                    r.log("createapikeyAsync(): Existing Maximo API Key apikeytokenid = " + response_getmaximoapikey.member[0].apikeytokenid);
                    // modify the href to use apikeytokenid number at the end of URL and assign to NGINX variable:
                    var apikeytokenid = response_getmaximoapikey.member[0].apikeytokenid;
                    var href = response_getmaximoapikey.member[0].href;                    
                    var segments = href.split("/");
                    segments[segments.length - 1] = "" + apikeytokenid;
                    var tmpUrl = segments.join("/");
                    r.log("createapikeySync():/getmaximoapikey - tmpUrl = " + tmpUrl);
                    var apiUrl = tmpUrl.replace (/(https?:\/\/)(.*?)(\/.*)/g, '$1' + 'maximo_api_server' + '$3');
                    r.log("createapikeySync():/getmaximoapikey - Changed hostname to maximo_api_server in href  = " + apiUrl);
                    r.variables.maximoapikeyref = apiUrl; // assign NGINX variable with modified href URL for /deletemaximoapikey location.                                  
                    //r.variables.maximoapikeyref = "http://maximo-project2.vip.iwater.ie/maxrest/oslc/os/IWMWMGENAPIKEYTOKEN/".concat(apikeytokenid); // assign NGINX variable - due to Maximo APIKEY Table constraint, only a single key can exist in the array.
                    r.log("createapikeyAsync(): r.variables.maximoapikeyref = " + r.variables.maximoapikeyref);
                    r.headersOut.maximoapikeyref = segments.join("/"); // assign HTTP response header - due to Maximo APIKEY Table constraint, only a single key can exist in the array.
                    r.log("createapikeyAsync(): r.headersOut.maximoapikeyref = " + r.headersOut.maximoapikeyref);
                    //
                    r.log("getMaximpAPIKey(): Test apikeytokenid > 0 for existing apikey to delete:  response_getmaximoapikey.member[0].apikeytokenid = " + response_getmaximoapikey.member[0].apikeytokenid);
                    if (apikeytokenid > 0) {
                        r.log("createapikeyAsync(): apikeytokenid > 0, calling subrequest /deletemaximoapkey.....");
                        r.subrequest("/deletemaximoapikey",
                            {
                                method: 'DELETE',
                            },
                            function (reply) {
                                if (reply.status == 200 || reply.status == 204) {
                                    r.log("createapikeyAsync()/deletemaximoapikey: Deleted existing user APIKEY " + r.variables.maximoapikeyref);
                                } else {
                                    r.log("createapikeyAsync()/deletemaximoapikey: Failed to delete existing user APIKEY " + r.variables.maximoapikeyref);
                                    r.log("createapikeyAsync()/deletemaximoapikey: Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                                    r.return(reply.status, "createapikeyAsync()/deletemaximoapikey: Error in response from subrequest " + reply.uri + "\n" + reply.responseBody);
                                    throw new Error("createapikeyAsync():/deletemaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
                                }
                            } // end of subrequest function(reply) statement block.
                        ); // end of r.subrequest function.
                    }
                } else {
                    deleteCommitDelayMillisec = 0;    // set wait interval = 0 msec.
                    r.log("createapikeyAsync(): NO MAXIMO USER APIKEYS FOUND - response.member.length = " + response_getmaximoapikey.member.length + " ASSIGN ZERO WAIT INTERVAL = " + deleteCommitDelayMillisec);

                }
                // Check if the /deletemaximoapikey operation has committed by calling /getmaximoapikey. 
                // If apikey still present then wait a few seconds to allow Maximo delete apikey operation to be committed - avoid a race condition on the next create operation.
                r.log("createapikeyAsync(): Test if DELETE has committed i.e. if Maximo API Key Table contains key for specified user - calling /getmaximoapikey.");
                r.subrequest("/getmaximoapikey",
                    {
                        method: 'GET',
                    },
                    function (reply) {
                        if (reply.status == 200) {                            
                            var response_getmaximoapikey;
                            try {
                                response_getmaximoapikey = JSON.parse(reply.responseBody);
                                r.log("createapikeyAsync():/getmaximoapikey - parse JSON response OK");
                            } catch(error) {
                                r.log("createapikeyAsync():/getmaximoapikey - JSON Parse response error = " + error);
                                reply.status = 596;
                                r.return(reply.status, error + "\n" + "createapikeyAsync():/getmaximoapikey reply.responseBody = " + reply.responseBody); // Error, return reply JSON string.                                
                                throw new Error("createapikeyAsync():/getmaximoapikey - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error); // Custom code error, stop NJS processing.
                            }
                            r.log("createapikeyAsync(): r.headersOut.SetCookie = " + r.headersOut.SetCookie);  // Check if WQebSphere is creating cookie for client browser.      
                            if (response_getmaximoapikey.member.length = 0) {
                                deleteCommitDelayMillisec = 0;    // set wait interval = 0 msec.
                                r.log("createapikeyAsync(): MAXIMO USER APIKEYS DELETE SUCCEEDED - response.member.length = " + response_getmaximoapikey.member.length + " ASSIGN ZERO WAIT INTERVAL = " + deleteCommitDelayMillisec);
                            } else {
                                deleteCommitDelayMillisec = 4000;    // set wait interval = 4000 msec.
                                r.log("createapikeyAsync()/getmaximoapikey: MAXIMO USER APIKEYS DELETE NOT COMMITTED - response.member.length = " + response_getmaximoapikey.member.length + " ASSIGN WAIT INTERVAL = " + deleteCommitDelayMillisec);
                            }                        
                        } else {                            
                            r.log("createapikeyAsync():/getmaximoapikey - Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                            r.return(reply.status, "createapikeyAsync():/getmaximoapikey - Error in response from subrequest " + reply.uri + "\n" + reply.responseBody);
                        }
                    } // end of subrequest function(reply) statement block.
                ); // end of r.subrequest function.
                //r.return(200, "createapikeyAsync(): Deleted existing user APIKEY " + r.variables.maximoapikeyref + "\n");

                // create apikey here. Try this even if the previous DELETE operation fails.
                r.log("createapikeyAsync(): CREATING APIKEY ASSIGN WAIT INTERVAL = " + deleteCommitDelayMillisec);
                var millisecondsToWait = deleteCommitDelayMillisec;
                setTimeout(function () {
                    // Whatever you want to do after the wait interval of millisecondsToWait:
                    r.log("createapikeyAsync(): calling subrequest /createmaximoapkey_admin.....");
                    r.subrequest("/createmaximoapikey_admin",
                        {
                            method: 'POST',
                        },
                        function (reply) {
                            if (reply.status == 200 || reply.status == 201) {                                
                                var response_createmaximoapikey_admin;
                                try {
                                    response_createmaximoapikey_admin = JSON.parse(reply.responseBody);
                                    r.log("createapikeyAsync():/createmaximoapikey_admin - parse JSON response OK");
                                } catch(error) {
                                    r.log("createapikeyAsync():/createmaximoapikey_admin - JSON Parse response error = " + error);
                                    reply.status= 596;
                                    r.return(reply.status, error + "\n" + "createapikeyAsync():/createmaximoapikey_admin reply.responseBody = " + reply.responseBody); // Error, return reply JSON string.
                                    throw new Error("createapikeyAsync():/createmaximoapikey_admin - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error); // Custom code error, stop NJS processing.
                                }
                                r.log("createapikeyAsync():/createmaximoapikey_admin -  Created APIKEY for USER: " + response_createmaximoapikey_admin.userid + " - " + response_createmaximoapikey_admin.apikey);
                                r.variables.maximo_apikeys_cache = "{\"apikey\":\"" + response_createmaximoapikey_admin.apikey + "\"}"; // Create Maximo Create API key response entry in token cache
                                r.log("createapikeyAsync():createmaximoapikey_admin -  Added user APIKEY to NGINX cache - " + r.variables.maximo_apikeys_cache);
                                parseApikey(r); // Current response now in API key-value store so use cache as input for validation and to populate response header maximoapikey
                                //r.return(reply.status, "createapikeyAsync(): Created user APIKEY " + response_createmaximoapikey_admin.userid + " " + response_createmaximoapikey_admin.apikey + "\n");
                            } else {
                                r.log("createapikeyAsync():/createmaximoapikey_admin - Failed to create user APIKEY ");
                                r.log("createapikeyAsync():/createmaximoapikey_admin - Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                                r.return(reply.status, "createapikeyAsync():/createmaximoapikey_admin - Error in response from subrequest " + reply.uri + "\n" + reply.responseBody);
                            }
                        } // end of subrequest function(reply) statement block.
                    ); // end of r.subrequest function.
                }, millisecondsToWait);
            } else {
                r.log("createapikeyAsync(): Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                r.return(reply.status, "Error in response from subrequest " + reply.uri + "\n" + reply.responseBody);
                //r.return(401); // Unexpected response, return 'auth required'
            }
        } // end of function(reply) callback statement block    
    ); // end of r.subrequest function
}

//--------------------------------------------------------
function _getapikey(r) {
    // Not called from any function at the moment.
    r.log("_getapikey(): calling subrequest /getmaximoapikey.....");
    r.subrequest("/getmaximoapikey",
        {
            method: 'GET',
        },
        function (reply) {
            if (reply.status == 200) {                
                var response_getmaximoapikey;
                try {
                    response_getmaximoapikey = JSON.parse(reply.responseBody);
                    r.log("_getapikey():/getmaximoapikey - parse JSON response OK");
                } catch(error) {
                    r.log("_getapikey():/getmaximoapikey - JSON Parse response error = " + error);
                    reply.status = 596;
                    r.return(reply.status, error + "\n" + "_getapikey():/getmaximoapikey reply.responseBody = " + reply.responseBody); // Error, return reply JSON string.
                    throw new Error("_getapikey():/getmaximoapikey - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error);  // Custom code error, stop NJS processing.
                }
                r.log("_getapikey()/getmaximoapikey: r.headersOut.SetCookie = " + r.headersOut.SetCookie);  // Check if WQebSphere is creating cookie for client browser.      
                if (response_getmaximoapikey.member.length > 0) {
                    r.log("_getapikey()/getmaximoapikey: MAXIMO USER APIKEYS FOUND - response_getmaximoapikey.member.length = " + response_getmaximoapikey.member.length);
                    r.log("_getapikey()/getmaximoapikey: Existing Maximo API Key href = " + response_getmaximoapikey.member[0].href);
                    r.log("_getapikey()/getmaximoapikey: Existing Maximo API Key apikeytokenid = " + response_getmaximoapikey.member[0].apikeytokenid);
                    //r.return(reply.status, "_getapikey(): MAXIMO USER APIKEYS FOUND - response_getmaximoapikey.member.length = " + response_getmaximoapikey.member.length + "\n"); // API Key Found, return success code.
                    r.return(reply.status, reply.responseBody); // API Key Found, return reply JSON string and HTTP status.                   
                } else {
                    r.log("_getapikey()/getmaximoapikey: NO MAXIMO USER APIKEYS FOUND - response_getmaximoapikey.member.length = " + response_getmaximoapikey.member.length);
                    r.error("_getapikey()/getmaximoapikey: NO MAXIMO USER APIKEYS FOUND - response_getmaximoapikey.member.length = " + response_getmaximoapikey.member.length);
                    r.return(reply.status, "_getapikey()/getmaximoapikey: NO MAXIMO USER APIKEYS FOUND - response_getmaximoapikey.member.length = " + response_getmaximoapikey.member.length + "\n"); // API Key Empty List, return success code.                    
                }
            } else {
                r.log("_getapikey()/getmaximoapikey: Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                r.return(reply.status, reply.responseBody); // Error, return reply JSON string.                
            }
        } // end of function(reply) callback statement block
    ); // end of r.subrequest function
}
//--------------------------------------------------------
function _deleteapikey(r) {
    // Called from deleteapikeyAsync()
    r.log("_deletekey(): calling subrequest /deletemaximoapkey.....");
    try {
        var res_status = "not_set";
        var res_uri;
        let res = r.subrequest("/deletemaximoapikey",
            {
                method: 'DELETE',
            },
            function (reply) {
                res_status = reply.status;
                res_uri = reply.uri;
                if (reply.status == 200 || reply.status == 204) {
                    r.log("_deletekey()/deletemaximoapikey: Reply Status = " + res_status + ", Deleted existing user APIKEY " + r.variables.maximoapikeyref);
                    r.return(reply.status, "_deletekey()/deletemaximoapikey: Deleted existing user APIKEY " + r.variables.maximoapikeyref + "\n"); 
                } else {
                    r.log("_deletekey()/deletemaximoapikey: Reply Status = " + res_status + ", Failed to delete existing user APIKEY " + r.variables.maximoapikeyref);
                    r.log("_deletekey()/deletemaximoapikey: Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);                    
                    r.return(reply.status, "_deletekey()/deletemaximoapikey: Failed to delete APIKEY for existing user " + r.headersIn['MAXIMO-USER-ID'] + ", Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody + "\n");
                }
            } // end of subrequest function(reply) statement block.
        ); // end of r.subrequest function. Note that the r.return operation cannot contain res_status as is is not set due to asynchronous operation.        
        //return res;
    } catch (error) {
        r.log("_deletekey()/deletemaximoapikey: Error in response from subrequest " + res_uri + ", Reply Status = " + res_status + "error = " + error);
        //r.return(596, "Error in response from subrequest " + res_uri + "\n");
        return error;
    }
}
//--------------------------------------------------------
function createapikeySync(r) {
    r.log("createapikeySync(): calling sub request /getmaximoapikey ..... MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
    var deleteflag = 0;
    var reply_getmaximoapikey;
    var reply_deletemaximoapikey;
    var reply_createmaximoapikey_admin;
    r.subrequest('/getmaximoapikey',{method: 'GET', body: ''})
        .then(reply => {
            reply_getmaximoapikey = reply;
            r.log("createapikeySync():/getmaximoapikey - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
            if (reply.status != 200) {
                r.log("createapikeySync():/getmaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString());
                throw new Error("createapikeySync():/getmaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
            } else {
                if (reply.responseBody.length > 0) {
                    r.log("createapikeySync():/getmaximoapikey - reply.responseBody.length = " + reply.responseBody.length);
                    r.log("createapikeySync():/getmaximoapikey - reply.responseBody = " + reply.responseBody + " " + reply.uri + " " + reply.status.toString());                    
                    var response;
                    try {
                        response = JSON.parse(reply.responseBody);
                        r.log("createapikeySync():/getmaximoapikey - parse JSON response OK");
                    } catch(error) {
                        r.log("createapikeySync():/getmaximoapikey - JSON Parse response error = " + error);                        
                        reply_getmaximoapikey.status = 596; // make NGINX terminate processing.
                        throw new Error("createapikeySync():/getmaximoapikey - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error);
                    }
                    if (response.member.length > 0 && response.member[0].apikeytokenid > 0) {
                        r.log("createapikeySync():/getmaximoapikey - Existing Maximo API Key JSON response = " + JSON.stringify(response));
                        r.log("createapikeySync():/getmaximoapikey - Existing Maximo API Key JSON response.member[0].apikeytokenid = " + response.member[0].apikeytokenid);
                        r.log("createapikeySync():/getmaximoapikey - Existing Maximo API Key JSON response.member[0].apikey = " + response.member[0].apikey);
                        // modify the href to use apikeytokenid number at the end of URL and assign to NGINX variable:
                        var apikeytokenid = response.member[0].apikeytokenid;
                        var href = response.member[0].href;
                        var segments = href.split("/");
                        segments[segments.length - 1] = "" + apikeytokenid;
                        var tmpUrl = segments.join("/");
                        r.log("createapikeySync():/getmaximoapikey - tmpUrl = " + tmpUrl);
                        var apiUrl = tmpUrl.replace (/(https?:\/\/)(.*?)(\/.*)/g, '$1' + 'maximo_api_server' + '$3');
                        r.log("createapikeySync():/getmaximoapikey - Changed hostname to maximo_api_server in href  = " + apiUrl);
                        r.variables.maximoapikeyref = apiUrl; // assign NGINX variable with modified href URL for /deletemaximoapikey location.
                        r.log("createapikeySync():/getmaximoapikey - NGINX variable r.variables.maximoapikeyref = " + r.variables.maximoapikeyref);
                        deleteflag = 1;   // There is an existing apikey to be deleted.
                        r.log("createapikeySync():/getmaximoapikey - Maximo apikey EXISTS in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                        return deleteflag;
                    } else {
                        r.log("createapikeySync():/getmaximoapikey - JSON OBJ response.member.length = " + response.member.length);
                        r.log("createapikeySync():/getmaximoapikey - Maximo API Key JSON response.member[0].apikeytokenid = " + response.member[0].apikeytokenid);
                        r.log("createapikeySync():/getmaximoapikey - Maximo apikey NOT FOUND in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                        deleteflag = 0;   // There is no existing apikey to delete.
                        return deleteflag;
                        //throw new Error("createapikeySync(): JSON OBJ - response.member.length = " + response.member.length);
                    }
                } else {
                    r.log("_createapikeey():/getmaximoapikey - reply.responseBody.length = " + reply.responseBody.length);
                    reply_getmaximoapikey.status = 596; // make NGINX terminate processing.
                    throw new Error("createapikeySync():/getmaximoapikey - reply body is empty for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.responseBody = " + reply.responseBody);
                }            
            }
        })
        .then(deleteflag => {
            if (deleteflag == 1) {
                r.log("createapikeySync(): calling sub request /deletemaximoapikey..... deleteflag = " + deleteflag + " MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", r.variables.maximoapikeyref = " + r.variables.maximoapikeyref);
                r.subrequest('/deletemaximoapikey', {method: 'DELETE', body: ''})
                    .then(reply => {
                        reply_deletemaximoapikey = reply;
                        r.log("createapikeySync():/deletemaximoapikey - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                        if (reply.status != 200 && reply.status != 204) {
                            r.log("createapikeySync():/deletemaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString());                            
                            throw new Error("createapikeySync():/deletemaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
                            //r.return(reply.status, reply.responseBody, "subrequest /deletemaximoapikey failed.");
                        } else {
                        return deleteflag;
                        }
                    })                    // do not use r.return here. The last subrequest in the chain has r.return().
                    .then(deleteflag => {
                        r.log("createapikeySync(): calling sub request /createmaximoapikey_admin....." + " MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                        r.subrequest('/createmaximoapikey_admin', {method: 'POST', body: ''})
                            .then(reply => {
                                reply_createmaximoapikey_admin = reply;
                                r.log("createapikeySync():/createmaximoapikey_admin - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                                if (reply.status != 200 && reply.status != 201) {
                                    r.log("createapikeySync():/createmaximoapikey_admin - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString());
                                    throw new Error("createapikeySync():/createmaximoapikey_admin - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
                                    //r.return(reply.status, reply.responseBody, "subrequest /createmaximoapikey_admin failed.");
                                } else {
                                    r.log("createapikeySync():/createmaximoapikey_admin - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                                    var response_createapikey;
                                    try {
                                        response_createapikey = JSON.parse(reply.responseBody);
                                        r.log("createapikeySync():/createmaximoapikey_admin - parse JSON response OK");
                                    } catch(error) {
                                        r.log("createapikeySync():/createmaximoapikey_admin - JSON Parse response error = " + error);
                                        reply_createmaximoapikey_admin.status = 596;
                                        throw new Error("createapikeySync():/createmaximoapikey_admin - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error);                                    
                                    }
                                    r.log("createapikeySync():/createmaximoapikey_admin Created APIKEY for USER: " + response_createapikey.userid + " - " + response_createapikey.apikey);
                                    r.variables.maximo_apikeys_cache = "{\"apikey\":\"" + response_createapikey.apikey + "\"}"; // Create Maximo Create API key response entry in token cache
                                    r.log("createapikeySync():/createmaximoapikey_admin Added user APIKEY to NGINX CACHE - " + r.variables.maximo_apikeys_cache);
                                    // Parse the cached API Key JSON object and assign the API key to a response header.                                                                   
                                    var apikeyscache_json;
                                    try {
                                        apikeyscache_json = JSON.parse(r.variables.maximo_apikeys_cache);
                                        r.log("createapikeySync():/createmaximoapikey_admin - parse JSON NGINX cache OK");
                                    } catch(error) {
                                        r.log("createapikeySync():/createmaximoapikey_admin - parse JSON NGINX cache error = " + error);                        
                                        reply_createmaximoapikey_admin.status = 596;
                                        throw new Error("createapikeySync():/createmaximoapikey_admin - parse JSON NGINX cache error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", r.variables.maximo_apikeys_cache = " + r.variables.maximo_apikeys_cache + ", JSON parse error =  " + error);                               
                                    }                                    
                                    r.log("createapikeySync():/createmaximoapikey_admin Maximo api Keys NGINX CACHE response - payload = " + r.variables.maximo_apikeys_cache);
                                    r.log("createapikeySync():/createmaximoapikey_admin Maximo API Keys NGINX CACHE response - apikey = " + apikeyscache_json.apikey);
                                    if (apikeyscache_json.apikey.length > 0) {
                                        r.body = apikeyscache_json;
                                        r.headersOut.maximoapikey = apikeyscache_json.apikey;
                                        r.log("createapikeySync():/createmaximoapikey_admin Assigned Maximo API Key to response header: maximoapikey. End subrequest /createmaximoapikey_admin and return to caller: location /_oauth2_token_cache_validation");
                                    } else {
                                        r.log("createapikeySync():/createmaximoapikey_admin Maximo API Key not found, End subrequest /createmaximoapikey_admin and return to caller: location /_oauth2_token_cache_validation");
                                    }
                                    r.return(reply.status, reply.responseBody)
                                }    
                            })        // Last sub request in the chain has r.return().
                            .catch(e => r.return(reply_createmaximoapikey_admin.status, e));  // End of subrequest /createmaximoapikey_admin as semicolon.                
                    })
                    .catch(e => r.return(reply_deletemaximoapikey.status, e));  // End of subrequest /deletemaximoapikey as semicolon.                   
            } else {
                r.log("createapikeySync(): NO apikey to delete, NOT calling sub request /deletemaximoapikey..... deleteflag = " + deleteflag + ", MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                deleteflag = 0;   // There is no existing apikey to delete.
                return deleteflag;
            }
        })
        // Repeat the createmaximoapikey_admin block of code for the case where deleteflag = 0. Breaking this block out as a separate function could upset the promise object synchronous behaviour:
        .then(deleteflag => {
            if (deleteflag == 0) {
                r.log("createapikeySync(): calling sub request /createmaximoapikey_admin..... deleteflag = " + deleteflag + " MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                r.subrequest('/createmaximoapikey_admin', {method: 'POST', body: ''})
                    .then(reply => {
                        reply_createmaximoapikey_admin = reply;
                        r.log("createapikeySync():/createmaximoapikey_admin - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                        if (reply.status != 200 && reply.status != 201) {
                            r.log("createapikeySync():/createmaximoapikey_admin - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString());
                            throw new Error("createapikeySync():/createmaximoapikey_admin - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
                            //r.return(reply.status, reply.responseBody, "subrequest /createmaximoapikey_admin failed.");
                        } else {
                            r.log("createapikeySync():/createmaximoapikey_admin - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);                            
                            var response_createapikey;
                            try {
                                response_createapikey = JSON.parse(reply.responseBody);
                                r.log("createapikeySync():/createmaximoapikey_admin - parse JSON response OK");
                            } catch(error) {
                                r.log("createapikeySync():/createmaximoapikey_admin - JSON Parse response error = " + error);
                                reply_createmaximoapikey_admin.status = 596;
                                throw new Error("createapikeySync():/createmaximoapikey_admin - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error);                        
                            }
                            r.log("createapikeySync():/createmaximoapikey_admin Created APIKEY for USER: " + response_createapikey.userid + " - " + response_createapikey.apikey);
                            r.variables.maximo_apikeys_cache = "{\"apikey\":\"" + response_createapikey.apikey + "\"}"; // Create Maximo Create API key response entry in token cache
                            r.log("createapikeySync():/createmaximoapikey_admin Added user APIKEY to NGINX CACHE - " + r.variables.maximo_apikeys_cache);
                            // Parse the cached API Key JSON object and assign the API key to a response header.
                            var apikeyscache_json;
                            try {
                                apikeyscache_json = JSON.parse(r.variables.maximo_apikeys_cache);
                                r.log("createapikeySync():/createmaximoapikey_admin - parse JSON NGINX cache OK");
                            } catch(error) {
                                r.log("createapikeySync():/createmaximoapikey_admin - parse JSON NGINX cache error = " + error);                        
                                reply_createmaximoapikey_admin.status = 596;
                                throw new Error("createapikeySync():/createmaximoapikey_admin - parse JSON NGINX cache error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", r.variables.maximo_apikeys_cache = " + r.variables.maximo_apikeys_cache + ", JSON parse error =  " + error);                            
                            }
                            r.log("createapikeySync():/createmaximoapikey_admin Maximo api Keys NGINX CACHE response - payload = " + r.variables.maximo_apikeys_cache);
                            r.log("createapikeySync():/createmaximoapikey_admin Maximo API Keys NGINX CACHE response - apikey = " + apikeyscache_json.apikey);
                            if (apikeyscache_json.apikey.length > 0) {
                                r.body = apikeyscache_json;
                                r.headersOut.maximoapikey = apikeyscache_json.apikey;
                                r.log("createapikeySync():/createmaximoapikey_admin Assigned Maximo API Key to response header: maximoapikey. End subrequest and return to caller: NGINX location /_oauth2_token_cache_validation");
                            } else {
                                r.log("createapikeySync():/createmaximoapikey_admin Maximo API Key not found, End subrequest and return to caller: NGINX location /_oauth2_token_cache_validation");
                            }
                            r.return(reply.status, reply.responseBody)
                        }
                    })        // Last sub request in the chain has r.return().
                    .catch(e => r.return(reply_createmaximoapikey_admin.status, e));  // End of subrequest /createmaximoapikey_admin as semicolon.
            }
        })
        .catch(e => r.return(reply_getmaximoapikey.status, e));      // End of sub request /getmaximoapikey
}
//--------------------------------------------------------
function deleteapikeySync(r) {
    r.log("deleteapikeySync(): calling sub request /getmaximoapikey ..... MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
    var deleteflag = 0;
    var reply_getmaximoapikey;
    var reply_deletemaximoapikey;
    r.subrequest('/getmaximoapikey', {method: 'GET', body: ''})
        .then(reply => {
            reply_getmaximoapikey = reply;
            r.log("deleteapikeySync():/getmaximoapikey - response from subrequest " + reply.uri + ", reply.status =  " + reply.status.toString() + ", reply.responseBody =  " + reply.responseBody + ", r.headersIn.MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
            if (reply.status != 200) {
                r.log("deleteapikeySync():/getmaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString());
                throw new Error("deleteapikeySync():/getmaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
            } else {
                if (reply.responseBody.length > 0) {
                    r.log("deleteapikeySync():/getmaximoapikey - reply.responseBody.length = " + reply.responseBody.length);
                    r.log("deleteapikeySync():/getmaximoapikey - reply.responseBody = " + reply.responseBody) + "\n";                    
                    var response;
                    try {
                        response = JSON.parse(reply.responseBody);
                        r.log("deleteapikeySync():/getmaximoapikey - parse JSON response OK");
                    } catch(error) {
                        r.log("deleteapikeySync():/getmaximoapikey - JSON Parse response error = " + error);
                        reply_getmaximoapikey.status = 596;
                        throw new Error("deleteapikeySync():/getmaximoapikey - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error);            
                    }
                    if (response.member.length > 0 && response.member[0].apikeytokenid > 0) {
                        r.log("deleteapikeySync():/getmaximoapikey - Existing Maximo API Key JSON response = " + JSON.stringify(response));
                        r.log("deleteapikeySync():/getmaximoapikey - Existing Maximo API Key JSON response.member[0].apikeytokenid = " + response.member[0].apikeytokenid);
                        r.log("deleteapikeySync():/getmaximoapikey - Existing Maximo API Key JSON response.member[0].apikey = " + response.member[0].apikey);                    
                        // modify the href to use apikeytokenid number at the end of URL and assign to NGINX variable:
                        var apikeytokenid = response.member[0].apikeytokenid;
                        var href = response.member[0].href;
                        var segments = href.split("/");
                        segments[segments.length - 1] = "" + apikeytokenid;
                        var tmpUrl = segments.join("/");
                        r.log("deleteapikeySync():/getmaximoapikey - tmpUrl = " + tmpUrl);
                        var apiUrl = tmpUrl.replace (/(https?:\/\/)(.*?)(\/.*)/g, '$1' + 'maximo_api_server' + '$3');
                        r.log("deleteapikeySync():/getmaximoapikey - Changed hostname to maximo_api_server in href  = " + apiUrl);
                        r.variables.maximoapikeyref = apiUrl; // assign NGINX variable with modified href URL for /deletemaximoapikey location.
                        r.log("deleteapikeySync():/getmaximoapikey - NGINX variable r.variables.maximoapikeyref = " + r.variables.maximoapikeyref);
                        deleteflag = 1;   // There is an existing apikey to be deleted.
                        r.log("deleteapikeySync():/getmaximoapikey - Maximo apikey EXISTS in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                        return deleteflag;
                    } else {
                        r.log("deleteapikeySync():/getmaximoapikey - JSON OBJ response.member.length = " + response.member.length);
                        r.log("deleteapikeySync():/getmaximoapikey - Maximo apikey NOT FOUND in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                        deleteflag = 0;   // There is no existing apikey to delete.
                        return deleteflag;                        
                    }   // End of inner if statement
                } else {
                    r.log("deleteapikeySync():/getmaximoapikey - reply.responseBody.length = " + reply.responseBody.length);
                    reply_getmaximoapikey.status = 596;
                    throw new Error("deleteapikeySync():/getmaximoapikey - reply body is empty for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.responseBody = " + reply.responseBody);
                }
            }            
        })
        .then(deleteflag => {
            if (deleteflag == 1) {
                r.log("deleteapikeySync(): calling sub request /deletemaximoapikey..... deleteflag = " + deleteflag + " MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", r.variables.maximoapikeyref = " + r.variables.maximoapikeyref);
                r.subrequest('/deletemaximoapikey', {method: 'DELETE', body: ''})
                    .then(reply => {
                        reply_deletemaximoapikey = reply;
                        r.log("deleteapikeySync():/deletemaximoapikey - response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                        if (reply.status != 200 && reply.status != 204) {
                            r.log("deleteapikeySync():/deletemaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString());
                            throw new Error("deleteapikeySync():/deletemaximoapikey - subrequest failed for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", reply.responseBody = " + reply.responseBody);
                        } else {
                            r.return(reply.status, reply.responseBody);
                        }                        
                    })                // do not use r.return here. The last subrequest in the chain has r.return().                      
                    .catch(e => r.return(reply_deletemaximoapikey.status, e));  // End of subrequest /deletemaximoapikey                    
            } else {
                r.log("deleteapikeySync(): NO apikey to delete, NOT calling sub request /deletemaximoapikey..... deleteflag = " + deleteflag + ", MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
                //r.log("deleteapikeySync():/deletemaximoapikey - response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                r.return(200, "deleteapikeySync(): NO apikey to delete, NOT calling sub request /deletemaximoapikey..... deleteflag = " + deleteflag + ", MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);
            }
        })
        .catch(e => r.return(reply_getmaximoapikey.status, e));      // End of sub request /getmaximoapikey
}
//--------------------------------------------------------
// The Maximo apikey cache uses the request header MAXIMO-USER-ID as the index-value.
// This function deletes any existing apikey (getmaximoapikey + deletemaximoapikey).
function deleteapikeyAsync(r) {
    r.variables.maximoapikeyref = "";
    var apikeytokenid = "";
    var href = "";
    r.log("deleteapikeyAsync(): JWT Claim user_name = " + r.variables.jwt_keycloak_user_name);
    r.log("deleteapikeyAsync(): MIP Header - MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID']);  // Temporary Header for Maximo UserId until Azure JWT Claim is assigned.
    r.log("deleteapikeyAsync(): Test if Maximo API Key Table contains key for specified user - calling /getmaximoapikey.");
    r.subrequest("/getmaximoapikey",
        {
            method: 'GET',
        },
        function (reply) {
            if (reply.status == 200) {  
                var response_getmaximoapikey;              
                try {
                    response_getmaximoapikey = JSON.parse(reply.responseBody);
                    r.log("deleteapikeyAsync():/getmaximoapikey - parse JSON response OK");
                } catch(error) {
                    r.log("deleteapikeyAsync():/getmaximoapikey - JSON Parse response error = " + error);
                    reply.status = 596;                   
                    r.return(reply.status, error + "\n" + "deleteapikeyAsync():/getmaximoapikey reply.responseBody = " + reply.responseBody); // Error, return reply JSON string.
                    throw new Error("deleteapikeyAsync():/getmaximoapikey - JSON Parse response error for MAXIMO-USER-ID = " + r.headersIn['MAXIMO-USER-ID'] + ", reply.status = " + reply.status.toString() + ", JSON parse error =  " + error); // Custom code error, stop NJS processing.
                }
                r.log("deleteapikeyAsync(): r.headersOut.SetCookie = " + r.headersOut.SetCookie);  // Check if WQebSphere is creating cookie for client browser.      
                if (response_getmaximoapikey.member.length > 0) {
                    r.log("deleteapikeyAsync(): MAXIMO USER APIKEYS FOUND - response.member.length = " + response_getmaximoapikey.member.length);
                    r.log("deleteapikeyAsync(): Existing Maximo API Key href = " + response_getmaximoapikey.member[0].href);
                    r.log("deleteapikeyAsync(): Existing Maximo API Key apikeytokenid = " + response_getmaximoapikey.member[0].apikeytokenid);
                    // modify the href to use apikeytokenid number at the end of URL and assign to NGINX variable:
                    apikeytokenid = response_getmaximoapikey.member[0].apikeytokenid;
                    href = response_getmaximoapikey.member[0].href;
                    var segments = href.split("/");
                    segments[segments.length - 1] = "" + apikeytokenid;
                    var tmpUrl = segments.join("/");
                    r.log("deleteapikeyAsync():/getmaximoapikey - tmpUrl = " + tmpUrl);
                    var apiUrl = tmpUrl.replace (/(https?:\/\/)(.*?)(\/.*)/g, '$1' + 'maximo_api_server' + '$3');
                    r.log("deleteapikeyAsync():/getmaximoapikey - Changed hostname to maximo_api_server in href  = " + apiUrl);
                    r.variables.maximoapikeyref = apiUrl; // assign NGINX variable with modified href URL for /deletemaximoapikey location.
                    //r.variables.maximoapikeyref = "http://maximo-project2.vip.iwater.ie/maxrest/oslc/os/IWMWMGENAPIKEYTOKEN/".concat(apikeytokenid); // assign NGINX variable - due to Maximo APIKEY Table constraint, only a single key can exist in the array.
                    r.log("deleteapikeyAsync(): r.variables.maximoapikeyref = " + r.variables.maximoapikeyref);
                    r.headersOut.maximoapikeyref = apiUrl; // assign HTTP response header - due to Maximo APIKEY Table constraint, only a single key can exist in the array.
                    r.log("deleteapikeyAsync(): r.headersOut.maximoapikeyref = " + r.headersOut.maximoapikeyref);
                    //
                    r.log("deleteapikeyAsync(): Test length > 0 for existing apikey to delete:  response_getmaximoapikey.member[0].apikeytokenid = " + response_getmaximoapikey.member[0].apikeytokenid);
                    if (apikeytokenid > 0) {
                        r.log("deleteapikeyAsync(): calling function /_deleteapikey.....");
                        _deleteapikey(r);
                        //_deleteapikey(r).then((data) => r.return(200, data)).catch((msg) => r.return(400, msg));
                    }
                } else {
                    r.log("deleteapikeyAsync(): NO MAXIMO USER APIKEYS FOUND - response.member.length = " + response_getmaximoapikey.member.length);
                    r.return(200, "deleteapikeyAsync(): NO MAXIMO USER APIKEYS FOUND - response.member.length = " + response_getmaximoapikey.member.length + "\n"); // API Key Empty List, return success code.
                }
            } else {
                r.log("deleteapikeyAsync(): Error in response from subrequest " + reply.uri + " " + reply.status.toString() + " " + reply.responseBody);
                r.return(reply.status, "Error in response from subrequest " + reply.uri + "\n" + ", reply.responseBody = " + reply.responseBody);
            }
        } // end of function(reply) callback statement block
    ); // end of r.subrequest function
}
//--------------------------------------------------------
function introspectAccessToken(r) {    
    //var response = JSON.parse(r.variables.token_test);
    //var response = JSON.parse(r.variables.token_test_mip);
    r.log("introspectAccessToken - parsing a JSON JWT: " + r.headersIn['JWT-Token']);
    var response = JSON.parse( r.headersIn['JWT-Token']);
    if (response.active) {
        // Convert all members of the response into response headers
        for (var p in response) {
            if (!response.hasOwnProperty(p)) continue;
            r.log("OAuth2 Token-" + p + ": " + response[p]);
            r.headersOut['Token-' + p] = response[p];
        }
        r.status = 204;
        //    r.sendHeader();
        r.return(200, "JWT Parsed Successfully----------" + "\n");
        r.finish();
    } else {
        r.return(401);
    }
}

//module.exports = { writeToken, readToken }
export default { readToken, writeToken, introspectAccessToken, validateAccessToken, validateAccessTokenCache, createapikeyCache, createapikeyAsync, deleteapikeyAsync, deleteapikeySync, _getapikey, createapikeySync }