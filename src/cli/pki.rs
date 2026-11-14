//! Explicit operator trust commands; normal serving still gates installation.
use super::*;
use caddy_compat_native::local_pki::{SystemTrustInstaller,TrustInstaller};
use tokio_util::sync::CancellationToken;

pub(super) fn command(name:&str,input:&[OsString])->Result<i32>{
    let mut specs=COMMON.to_vec();
    specs.extend([
        Flag{name:"ca",short:None,kind:Kind::Text},
        Flag{name:"address",short:None,kind:Kind::Text},
        Flag{name:"adapter",short:Some(b'a'),kind:Kind::Text},
    ]);
    if name=="untrust"{specs.push(Flag{name:"cert",short:Some(b'p'),kind:Kind::Text});}
    let flags=args::parse(input,&specs)?;
    if flags.boolean("help"){
        println!("Usage: caddy-compat-native {name} [--ca ID] [--address ADDR] [--config PATH] [--adapter caddyfile]{}",if name=="untrust"{" | --cert PATH"}else{""});
        return Ok(0)
    }
    ensure!(flags.positional.is_empty(),"trust command accepts no positional arguments");
    let explicit_cert=nonempty(flags.text("cert"));
    ensure!(explicit_cert.is_none()||["ca","address","config","adapter"].iter().all(|key|nonempty(flags.text(key)).is_none()),"--cert conflicts with admin selection flags");
    let address=if explicit_cert.is_none(){
        if let Some(address)=nonempty(flags.text("address")){address.to_str().context("invalid admin address")?.to_owned()}
        else{
            let configured=if nonempty(flags.text("config")).is_some(){
                let raw=config::load(flags.text("config"),flags.text("adapter"))?;
                let value=admin_json::decoded_typed(&raw).map_err(|e|anyhow!(e.category))?;
                value.get("admin").and_then(|v|v.get("listen")).filter(|v|!v.is_null())
                    .map(|v|v.as_str().map(str::to_owned).context("invalid admin listen address")).transpose()?
            }else{None};
            configured.filter(|v|!v.is_empty()).unwrap_or_else(||std::env::var("CADDY_ADMIN").unwrap_or_else(|_|"localhost:2019".into()))
        }
    }else{String::new()};
    let file=explicit_cert.map(PathBuf::from);
    let ca=nonempty(flags.text("ca")).map(|v|v.to_str().context("invalid CA identifier")).transpose()?.unwrap_or("local");
    ensure!(ca.len()<=1024&&!ca.contains(['\0','/','\\']),"invalid CA identifier");
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async{
        let pem=if let Some(file)=file{read_file(&file,1024*1024)?}
        else{
            let(client,origin,unix)=serving::admin_endpoint(&address)?;
            let mut endpoint=url::Url::parse(&origin)?;
            endpoint.path_segments_mut().map_err(|_|anyhow!("invalid admin origin"))?.extend(["pki","ca",ca]);
            let mut request=client.get(endpoint).timeout(std::time::Duration::from_secs(30));
            if !unix{request=request.header("Origin",&origin);}
            let mut response=request.send().await.map_err(|_|anyhow!("admin CA request failed"))?;
            ensure!(response.status().is_success(),"admin CA request failed: HTTP {}",response.status().as_u16());
            let mut bytes=zeroize::Zeroizing::new(Vec::new());
            while let Some(chunk)=response.chunk().await?{
                ensure!(bytes.len().checked_add(chunk.len()).is_some_and(|n|n<=1024*1024),"admin CA response exceeds limit");
                bytes.try_reserve(chunk.len())?;bytes.extend_from_slice(&chunk);
            }
            let value=admin_json::decoded_typed(&bytes).map_err(|e|anyhow!(e.category))?;
            value.get("root_certificate").and_then(serde_json::Value::as_str).context("admin CA response has no root certificate")?.as_bytes().to_vec()
        };
        let installer=SystemTrustInstaller::discover().await?;
        if name=="trust"{installer.install(&pem,CancellationToken::new()).await?;}
        else{installer.uninstall(&pem,CancellationToken::new()).await?;}
        Ok(0)
    })
}
