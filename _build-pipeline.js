/* Build pipeline correlation — included in dashboard bundle */
const PIPELINE_SCANNERS = new Set(['sca','sast','container']);

const PIPELINE_PRESETS = {
  'SCA-001': {
    repo:{name:'payments-platform/transaction-router',branch:'main',commitShort:'a3f8e92',author:'Sarah Chen',ageHours:72},
    prStatus:{state:'merged',prNumber:1247,prUrl:'#',detail:'Two reviewers approved; SCA gate non-blocking when dep added'},
    build:{system:'Jenkins',buildId:'build-4521',buildUrl:'#',ageHours:48,status:'passed',note:'SCA scan ran; KEV unknown at build time',environment:'production',envKey:'prod',envLabel:'Production CI',agentPool:'k8s-build-agents-prod-us-east-1',region:'us-east-1'},
    artifact:{name:'registry.internal/transaction-router',version:'v4.2.1',digest:'sha256:3f2a9c1e…',registry:'JFrog Artifactory'},
    registry:{name:'JFrog Artifactory',path:'prod-releases/transaction-router',scanStatus:'scanned · digest retained'},
    deployment:{tool:'ArgoCD',app:'transaction-router-prod',cluster:'eks-prod-us-east-1',namespace:'payments',podCount:12,syncedAgo:'2 days ago'},
    reachability:{confirmed:true,callsPerDay:'14,000×/day',entryPoint:'HTTP /api/charge handler',sensor:'Endor Labs runtime'},
    dependencyChain:['transaction-router','spring-boot-starter-web 2.5.4','spring-core 5.3.9','spring-jcl 5.3.9','log4j-core 2.14.1'],
    manifestFile:'pom.xml',resolvedVersion:'2.14.1'
  },
  'CON-001': {
    repo:{name:'payments-platform/transaction-router',branch:'main',commitShort:'a3f8e92',author:'Sarah Chen',ageHours:72},
    prStatus:{state:'merged',prNumber:1247,detail:'Image built from same commit as SCA finding'},
    build:{system:'GitHub Actions',buildId:'workflow-8821',ageHours:48,status:'passed',note:'Kaniko image build · Trivy gate warn-only',environment:'production',envKey:'prod',envLabel:'Production CI',agentPool:'gha-hosted · larger runners',region:'us-east-1'},
    artifact:{name:'registry.internal/transaction-router',version:'v4.2.1',digest:'sha256:3f2a9c1e…',registry:'JFrog Artifactory'},
    registry:{name:'JFrog Artifactory',path:'prod-releases',scanStatus:'3 older digests still pullable'},
    deployment:{tool:'ArgoCD',app:'transaction-router-prod',cluster:'eks-prod-us-east-1',namespace:'payments',podCount:12,syncedAgo:'2 days ago'},
    baseImageLineage:[
      {name:'transaction-router:v4.2.1',layer:'app'},
      {name:'internal-base/java17:2024-01',layer:'intermediate'},
      {name:'eclipse-temurin:17-jre',layer:'base'},
      {name:'ubuntu:22.04',layer:'os'}
    ],
    vulnerableLayer:'app',
    note:'Same root cause as SCA-001 — log4j in app layer, not base image',
    reachability:{confirmed:true,callsPerDay:'JndiLookup.lookup() via bundled log4j-core',entryPoint:'HTTP /api/charge',sensor:'Endor Labs runtime (folded into Runtime controls)'}
  },
  'SAST-001': {
    repo:{name:'payments-platform/payments-api',branch:'main',commitShort:'b7c21de',author:'Marcus Webb',ageHours:96},
    prStatus:{state:'precaught',prNumber:1189,detail:'Semgrep commented on PR; merged before DAST confirmation'},
    build:{system:'GitLab CI',buildId:'pipeline-33902',ageHours:60,status:'passed',note:'SAST gate failed — override by platform lead',environment:'production',envKey:'prod',envLabel:'Production CI',agentPool:'gitlab-runner-prod · docker',region:'us-east-1'},
    artifact:{name:'payments-api',version:'payments-api-2.8.0.war',digest:'sha256:91ab…',registry:'Nexus releases'},
    registry:{name:'Nexus Repository Manager',path:'releases/payments-api',scanStatus:'artifact retained'},
    deployment:{tool:'Spinnaker',app:'payments-api-prod',cluster:'eks-prod-us-east-1',namespace:'payments',podCount:8,syncedAgo:'3 days ago'},
    reachability:{confirmed:true,callsPerDay:'~2,400×/day',entryPoint:'POST /charge from internet ALB',sensor:'Contrast IAST + prod traces'}
  }
};

function bpAge(h){return h<24?`${h}h ago`:`${Math.floor(h/24)} day${Math.floor(h/24)>1?'s':''} ago`;}
function bpRepoName(asset){return asset.includes(':')?asset.split(':')[0]:asset.replace(/\s*\(.*\)/,'').trim();}

const BP_BUILD_ENVS=[
  {environment:'production',envKey:'prod',envLabel:'Production CI',agentPool:'k8s-build-agents-prod-us-east-1',region:'us-east-1'},
  {environment:'staging',envKey:'staging',envLabel:'Staging CI',agentPool:'k8s-build-agents-stg-us-east-1',region:'us-east-1'},
  {environment:'development',envKey:'dev',envLabel:'Development CI',agentPool:'github-hosted · ubuntu-22.04',region:'us-west-2'}
];

function bpApplyBuildEnv(build,n){
  const env=BP_BUILD_ENVS[n%BP_BUILD_ENVS.length];
  return {...build,...env};
}

function bpBuildEnvLine(b){
  if(!b) return '';
  return `${b.envLabel||b.environment} · ${b.system} · ${b.agentPool||'default agents'}${b.region?` · ${b.region}`:''}`;
}

function bpBuildGraphHint(bp){
  if(!bp?.build) return {label:'Build',sub:'',sub2:''};
  const b=bp.build;
  const env=String(b.envLabel||b.environment||'').replace('Production','Prod').replace('Staging','Stg').replace('Development','Dev');
  const sys=String(b.system||'').replace('GitHub Actions','GHA').replace('Azure Pipelines','Azure CI').replace('GitLab CI','GitLab');
  return {label:'Build',sub:b.buildId,sub2:`${env} · ${sys}`.trim()};
}

function buildBuildPipeline(seed,sid){
  if(!PIPELINE_SCANNERS.has(sid)) return null;
  if(PIPELINE_PRESETS[seed.id]) return {...PIPELINE_PRESETS[seed.id]};
  const n=seed.id.charCodeAt(4)+seed.id.charCodeAt(5);
  const repo=bpRepoName(seed.asset);
  const orgRepo=`payments-platform/${repo}`.replace(/\/+/g,'/');
  const authors=['Sarah Chen','Marcus Webb','Priya Nair','James Okonkwo'];
  const systems=['Jenkins','GitHub Actions','GitLab CI','CircleCI','Azure Pipelines'];
  const prStates=['merged','merged','precaught','blocked'];
  const prState=prStates[n%4];
  const base={
    repo:{name:orgRepo,branch:'main',commitShort:(n*17%0xffff).toString(16).slice(0,7),author:authors[n%4],ageHours:48+(n%96)},
    prStatus:{state:prState,prNumber:1100+(n%200),prUrl:'#',detail:prState==='merged'?'Security gate passed at merge':prState==='precaught'?'Fixed in follow-up PR before merge':'Blocked at PR — override for hotfix'},
    build:bpApplyBuildEnv({system:systems[n%5],buildId:`build-${4000+n}`,buildUrl:'#',ageHours:36+(n%48),status:n%7===0?'failed':'passed',note:'Pipeline scan completed'},n),
    artifact:{name:sid==='container'?`registry.internal/${repo}`:`${repo}`,version:sid==='container'?`${repo}:v${4+(n%3)}.${n%10}`:`v2.${n%9}.0`,digest:`sha256:${(n*991).toString(16).slice(0,4)}…`,registry:'JFrog Artifactory'},
    registry:{name:'JFrog Artifactory',path:'prod-releases',scanStatus:'digest on file'},
    deployment:{tool:'ArgoCD',app:`${repo.replace(/[^a-z0-9-]/gi,'-')}-prod`,cluster:'eks-prod-us-east-1',namespace:seed.owner.split(' ')[0].toLowerCase(),podCount:4+(n%20),syncedAgo:bpAge(36+(n%48))}
  };
  if(sid==='sca'){
    base.reachability={confirmed:seed.score>=7,callsPerDay:seed.score>=7?'1,200×/day':'Not loaded at runtime',entryPoint:seed.internet?'Inbound API traffic':'Internal batch only',sensor:'Runtime SBOM sensor'};
    base.dependencyChain=[repo,'spring-boot-starter-web','spring-core',seed.cve?seed.cve.replace('CVE-','lib-'):'vuln-lib'];
    base.manifestFile=n%2?'pom.xml':'package-lock.json';
    base.resolvedVersion=`${2+(n%3)}.${10+(n%5)}.${n%10}`;
  }
  if(sid==='sast'){
    base.reachability={confirmed:seed.score>=7.5,callsPerDay:seed.score>=7.5?'Called from prod entry':'Dead code path — never invoked',entryPoint:seed.internet?'/api public routes':'Internal admin only',sensor:'IAST + APM traces'};
  }
  if(sid==='container'){
    base.baseImageLineage=[
      {name:`${repo}:v4.${n%3}`,layer:'app'},
      {name:'internal-base/java17:2024-01',layer:'intermediate'},
      {name:'eclipse-temurin:17-jre',layer:'base'},
      {name:'ubuntu:22.04',layer:'os'}
    ];
    base.vulnerableLayer=n%5===0?'os':n%3===0?'base':'app';
    base.note='Image built from application repo Dockerfile';
  }
  return base;
}
