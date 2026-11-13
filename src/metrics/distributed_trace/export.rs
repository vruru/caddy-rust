//! Trace exporters reuse the actual native OTLP transport and its DATA owners.
//! Only the tracked driver invokes export; SDK callbacks never perform I/O.
use super::config::{Settings,Exporter};
use crate::metrics;
use anyhow::{Result,ensure};
use opentelemetry_otlp::{Protocol,SpanExporter,WithExportConfig,WithHttpConfig};
use opentelemetry_sdk::trace::{SpanData,SpanExporter as _};
use std::{collections::BTreeMap,io::Read,sync::{Arc,Mutex},time::Duration};
use tokio_util::sync::CancellationToken;
type Active=Arc<Mutex<Option<Arc<metrics::transport::Credit>>>>;
enum Sink {
 None,
 Http(SpanExporter,Active,Arc<metrics::transport::Transport>),
 Grpc(metrics::grpc::Grpc,opentelemetry_sdk::Resource),
 Console(Arc<metrics::console_writer::Writer>),
}
pub(super) struct Plan{sink:Sink,pub timeout:Duration,resource:opentelemetry_sdk::Resource}
struct Env(BTreeMap<String,String>);
impl Env {
 fn read()->Result<Self>{
  let mut vars=BTreeMap::new();let mut bytes=0usize;
  for key in ["HTTP_PROXY","http_proxy","HTTPS_PROXY","https_proxy","ALL_PROXY","all_proxy","NO_PROXY","no_proxy","OTEL_RESOURCE_ATTRIBUTES","OTEL_SERVICE_NAME"].into_iter().map(str::to_owned).chain(
   ["OTEL_EXPORTER_OTLP_","OTEL_EXPORTER_OTLP_TRACES_"].into_iter().flat_map(|prefix|
    ["ENDPOINT","PROTOCOL","HEADERS","COMPRESSION","TIMEOUT","INSECURE","CERTIFICATE","CLIENT_CERTIFICATE","CLIENT_KEY"].map(move|suffix|format!("{prefix}{suffix}")))) {
   if let Ok(value)=std::env::var(&key) {
    bytes=bytes.checked_add(key.len()).and_then(|n|n.checked_add(value.len())).filter(|n|*n<=16<<10).ok_or_else(||anyhow::anyhow!("trace exporter settings exceed 16 KiB"))?;
    vars.insert(key,value);
   }
  }
  Ok(Self(vars))
 }
 fn value(&self,key:&str)->Option<&str>{self.0.get(key).map(String::as_str).filter(|v|!v.is_empty())}
 fn signal(&self,name:&str)->Option<&str>{self.value(&format!("OTEL_EXPORTER_OTLP_TRACES_{name}")).or_else(||self.value(&format!("OTEL_EXPORTER_OTLP_{name}")))}
 fn file(&self,name:&str,left:&mut usize,process:&metrics::Process,credit:&metrics::Metadata)->Result<Option<Vec<u8>>>{
  let Some(path)=self.signal(name)else{return Ok(None)};
  let mut file=std::fs::File::open(path).map_err(|_|anyhow::anyhow!("opening trace TLS material failed"))?;
  ensure!(file.metadata()?.is_file(),"trace TLS material must be a regular file");
  let mut bytes=Vec::new();let mut input=[0u8;8192];
  loop{let n=file.read(&mut input)?;if n==0{break}
   ensure!(bytes.len()+n<=1<<20&&n<=*left,"trace TLS material exceeds per-file or total limit");
   credit.pay(process,(n*32)as u32)?;bytes.try_reserve(n)?;bytes.extend_from_slice(&input[..n]);*left-=n;
  }
  Ok(Some(bytes))
 }
}
/// Captured once for the generation. Every independent transport uses the
/// same checked TLS file bytes; a replacement on disk cannot split its trust.
pub(super) struct Inputs{env:Env,timeout:Duration,ca:Option<Vec<u8>>,cert:Option<Vec<u8>>,key:Option<Vec<u8>>}
impl Inputs{
 pub fn prepare(settings:&Settings,process:&Arc<metrics::Process>,metadata:&metrics::Metadata)->Result<Self>{
  // Bound resource environment strings before the SDK resource detector runs.
  let env=Env::read()?;
  let timeout=settings.timeout.min(env.signal("TIMEOUT").and_then(|v|v.parse::<u64>().ok()).filter(|v|*v>0).map(Duration::from_millis).unwrap_or(Duration::from_secs(10)));
  ensure!(tokio::time::Instant::now().checked_add(timeout).is_some(),"trace export deadline exceeds platform range");
  let mut result=Self{env,timeout,ca:None,cert:None,key:None};
  if !settings.disabled&&!settings.exporters.is_empty()&&settings.exporters[0]==Exporter::Otlp{
   let mut left=3<<20;
   result.ca=result.env.file("CERTIFICATE",&mut left,process,metadata)?;
   result.cert=result.env.file("CLIENT_CERTIFICATE",&mut left,process,metadata)?;
   result.key=result.env.file("CLIENT_KEY",&mut left,process,metadata)?;
   ensure!(result.cert.is_some()==result.key.is_some(),"trace client certificate and key must be configured together");
  }
  Ok(result)
 }
}
impl Plan {
 pub fn prepare(settings:&Settings,input:&Inputs,metadata:Arc<metrics::Metadata>,resource:&opentelemetry_sdk::Resource,process:&metrics::Process)->Result<Arc<Self>>{
  let env=&input.env;let timeout=input.timeout;let(ca,cert,key)=(&input.ca,&input.cert,&input.key);
  let sink=if settings.disabled||settings.exporters.is_empty(){Sink::None}
   else if settings.exporters[0]==Exporter::Console{Sink::Console(metrics::console_writer::Writer::prepare()?)}
   else {
    match env.signal("PROTOCOL").unwrap_or("http/protobuf"){
     "http/protobuf"=>{
      let endpoint=env.signal("ENDPOINT").unwrap_or("http://localhost:4318").parse().map_err(|_|anyhow::anyhow!("invalid trace HTTP endpoint"))?;
      let connector=crate::http_runtime::metrics_client::Connector::prepare(endpoint,ca.as_deref(),cert.as_deref().zip(key.as_deref()),timeout,CancellationToken::new(),metadata,false,process)?;
      let transport=metrics::transport::Transport::new(connector,timeout,false);
      let active=Arc::new(Mutex::new(None));
      let mut exporter=SpanExporter::builder().with_http().with_protocol(Protocol::HttpBinary).with_timeout(timeout)
       .with_http_client(metrics::export::native_client(transport.clone(),active.clone()))
       .with_max_request_body_size(32<<20).build().map_err(|_|anyhow::anyhow!("preparing trace HTTP exporter failed"))?;
      exporter.set_resource(resource);Sink::Http(exporter,active,transport)
     }
     "grpc"=>{
      let raw=env.signal("ENDPOINT").unwrap_or("http://localhost:4317");
      let endpoint=if raw.starts_with("http://")||raw.starts_with("https://"){raw.to_owned()}else{format!("{}://{raw}",if env.signal("INSECURE")==Some("true"){"http"}else{"https"})};
      Sink::Grpc(metrics::grpc::Grpc::prepare(endpoint,env.signal("HEADERS").map(str::to_owned),env.signal("COMPRESSION").map(str::to_owned),ca.as_deref(),cert.as_deref().zip(key.as_deref()),timeout,metadata,process)?,resource.clone())
     }
     _=>anyhow::bail!("unsupported trace OTLP protocol"),
    }
   };
  Ok(Arc::new(Self{sink,timeout,resource:resource.clone()}))
 }
 pub fn resource(&self)->&opentelemetry_sdk::Resource{&self.resource}
 pub fn console(&self)->Option<Arc<metrics::console_writer::Writer>>{if let Sink::Console(writer)=&self.sink{Some(writer.clone())}else{None}}
 pub async fn export(&self,data:Vec<SpanData>,credit:Arc<metrics::transport::Credit>)->Result<()>{
  match &self.sink{
   Sink::None=>Ok(()),
   Sink::Http(exporter,active,_)=>{
    *active.lock().unwrap_or_else(|e|e.into_inner())=Some(credit);
    let _guard=ActiveGuard(active.clone());exporter.export(data).await.map_err(|_|anyhow::anyhow!("trace HTTP export failed"))
   }
   Sink::Grpc(exporter,resource)=>exporter.export_traces(&data,resource,credit).await,
   Sink::Console(_)=>anyhow::bail!("console trace batch requires its bounded writer owner"),
  }
 }
 pub async fn shutdown(&self){
  match &self.sink {
   Sink::Http(exporter,_,transport)=>{let _=exporter.shutdown();transport.shutdown().await;}
   Sink::Grpc(exporter,_)=>exporter.shutdown().await,
   Sink::Console(writer)=>writer.shutdown().await,
   Sink::None=>{},
  }
 }
}
struct ActiveGuard(Active);
impl Drop for ActiveGuard{fn drop(&mut self){let credit=self.0.lock().unwrap_or_else(|e|e.into_inner()).take();drop(credit);}}
