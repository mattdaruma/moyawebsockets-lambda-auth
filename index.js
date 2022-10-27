const AWS = require("aws-sdk")
const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider()
const { CognitoJwtVerifier } = require("aws-jwt-verify")

exports.handler = async function(event, context, callback) {
    console.log('Deployed through Pipeline')
  const verifier = CognitoJwtVerifier.create({
    userPoolId: event.stageVariables.userPoolId,
    tokenUse: "access",
    clientId: event.stageVariables.clientId,
  })
  try {
    var tokenPayload = await verifier.verify(event.queryStringParameters.Authorization)
    var userData = await cognitoidentityserviceprovider.getUser({
        AccessToken: event.queryStringParameters.Authorization
    }).promise()
    var authResponse = {}
    authResponse.principalId = 'me'
    var policyDocument = {}
    policyDocument.Version = '2012-10-17'
    policyDocument.Statement = []
    var allowInvokeApi = {}
    allowInvokeApi.Action = 'execute-api:Invoke'
    allowInvokeApi.Effect = 'Allow'
    allowInvokeApi.Resource = event.methodArn
    policyDocument.Statement[0] = allowInvokeApi
    authResponse.policyDocument = policyDocument
    authResponse.context = {}
    for(let att of userData.UserAttributes){
        authResponse.context[att.Name] = att.Value
    }
    authResponse.context.token = event.queryStringParameters.Authorization
    authResponse.context.username = tokenPayload.username
    authResponse.context.sub = tokenPayload.sub
    authResponse.context.rolesPDS = tokenPayload['cognito:groups']?.join('||') ?? ''
    callback(null, authResponse)
  } catch(err) {
    console.log('Auth Error', err)
    callback("Unauthorized")
  }
}