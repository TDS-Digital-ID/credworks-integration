import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as core from '@unsw-vc/identity-core-node';
import {openGeneric} from '../tool/generic-http.ts';

test('public presentation refuses four core-signed unsupported DCQL controls without writing',async()=>{
 const directory=mkdtempSync(join(tmpdir(),'vc408-query-'));
 try {
  const did='did:web:verifier.example', keyId=did+'#key-1';
  const verifierJwk=core.persistentSigningKey({path:join(directory,'verifier.key'),unlockKey:core.randomUrlSafe(32),keyId,create:true});
  const document=JSON.stringify(core.buildDidWebDocument(did,[verifierJwk]));
  const stateDir=join(directory,'holder');mkdirSync(stateDir,{mode:0o700});
  const config={registryOrigin:'https://registry.example',registryDid:'did:web:registry.example',trustAnchorJwk:verifierJwk,providerOrigin:'https://provider.example',providerDid:'did:web:provider.example',providerJwk:verifierJwk,issuerOrigin:'https://issuer.example',issuerManagementOrigin:'http://127.0.0.1:29280',issuerManagementToken:'test-only',verifierOrigin:'https://verifier.example',verifierManagementOrigin:'http://127.0.0.1:29281',verifierManagementToken:'test-only',stateDir,configurationId:'entitlement',definitionId:'https://issuer.example/definitions/entitlement',definitionVersion:'1',credentialType:'NeutralEntitlement',profileName:'check',claimPaths:[['credentialSubject','enabled']],authorizationPath:'/issuer-authorizations/00000000-0000-4000-8000-000000000001.jwt',permissionPath:'/scoped-verifier-permissions/00000000-0000-4000-8000-000000000002.jwt',statusKeyId:'did:web:issuer.example#key-1',statusPublicJwk:verifierJwk};
  const requestUri=config.verifierOrigin+'/request/negative';
  let signed='',writes=0;
  const client=async(url,options)=>{
   if(options.method!=='GET'){writes++;throw Error('UNEXPECTED_WRITE');}
   const text=url===requestUri?signed:url===core.didWebToHttpsUrl(did)?document:'';
   // Empty unused publication responses cannot confer authority; every mutation must
   // refuse the authenticated request before those bytes are consumed as a grant.
   return {status:200,text,json:()=>JSON.parse(text)};
  };
  const flow=openGeneric(config,client);
  const mutations=[x=>x.credential_sets=[],x=>x.credentials[0].claim_sets=[],x=>x.credentials[0].meta.trusted_authorities=[],x=>x.credentials[0].claims[0].values=[false]];
  for(const mutate of mutations){
   const now=Math.floor(Date.now()/1000);
   const dcql={credentials:[{id:'check',format:'vc+sd-jwt',meta:{type_values:[['https://www.w3.org/2018/credentials#VerifiableCredential','NeutralEntitlement']]},claims:[{path:['credentialSubject','enabled']}]}]};
   mutate(dcql);
   signed=core.signCompactJwsJson({keyId,header:{alg:'ES256',typ:'oauth-authz-req+jwt',kid:keyId},payload:{client_id:'decentralized_identifier:'+did,response_type:'vp_token',response_mode:'direct_post',response_uri:config.verifierOrigin+'/oid4vp/response/negative',nonce:core.randomUrlSafe(32),state:core.randomUrlSafe(32),iat:now,exp:now+120,aud:'https://self-issued.me/v2',purpose:'Negative consent test',credworks_scalar:{credential_issuer_did:'did:web:issuer.example',credential_issuer_key_id:'did:web:issuer.example#key-1',definition_id:config.definitionId,definition_version:config.definitionVersion,authorization_path:config.authorizationPath,permission_path:config.permissionPath,profile_name:config.profileName},dcql_query:dcql}});
   await assert.rejects(flow.present({request_uri:requestUri},{}),{message:'REQUEST_SCOPE_NOT_PERMITTED'});
   assert.equal(writes,0);
  }
 }finally{rmSync(directory,{recursive:true,force:true});}
});
