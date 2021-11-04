use crate::*;
use crate::config::*;
use std::error::Error;
use std::fs::{File,read_to_string};
use std::path;
use std::env;
use std::io::{Read,Write};


#[macro_export]
macro_rules! dprintln {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ({
        if cfg!(debug_assertions){
            print!("[debug] ");
            println!($($arg)*);
        }
    })
}

lazy_static! {
    static ref hashcat_format:   Regex = Regex::new(r#"([\d\w\S\\\.\-])+:([\d])+:[a-f0-9]{32}:[a-f0-9]{32}:::"#).unwrap();
    static ref secrets_format:   Regex = Regex::new(r#"[\d\w\S\.\-]+[/|\\][\d\w\.\-]+:([^\s(:::)]*)$"#).unwrap();
    static ref userprinc_format: Regex = Regex::new(r#"[\d\w\S\.\-]+@[\d\w\.\-]+:([\S]*)$"#).unwrap();
    static ref just_user_princ_format: Regex = Regex::new(r#"([\d\S\w\.\-])+@{1}([\d\w\.\-][^:\s])+$"#).unwrap();
    static ref computer_format: Regex = Regex::new(r#"^([^@:\/\[\]][\d\w\.\-]+\.)+[\d\w\.\-]+$"#).unwrap();
}

#[derive(Debug)]
pub struct Neo4jConfig {
   pub uri:  String,
   pub user: String,
   pub pass: String,
}

impl Neo4jConfig {
    pub fn get_creds()->Option<Self>{
        // check hardcoded config.rs first
        if !USERNAME.is_empty() && !PASSWORD.is_empty() &&!SERVER.is_empty() {
            dprintln!("using hardcoded credentials");
            return Some(Neo4jConfig{
                uri:SERVER.to_string(),
                user:USERNAME.to_string(),
                pass:PASSWORD.to_string(),
            });
        }
        Neo4jConfig::get_from_file()
    }

    pub fn get_from_file()->Option<Self>{
        // try and load from $HOME/.bhdb
        let dir = env::var("HOME");
        if let Err(e) = dir{
            eprintln!("error resolving HOME env var...:{}",e.to_string());
            return None;
        }

        let mut pb = std::path::PathBuf::from(&dir.unwrap());
        pb.push(FILENAME);
        if !pb.exists(){
            // lets create one 
            eprintln!(r#"file {} does not exist, please create it with the following contents:
                      user=NEO4J_USER
                      pass=NEO4J_PASS
                      server=192.168.1.39:7687
                      (replace with your own values obviously)
                      alternatively, you can use can edit config.rs and recompile
                      "#,pb.to_str().unwrap());
            return None;
        } 
        // parse the data in the existing file
        let data = pb.to_str().map(|b| std::fs::read_to_string(b)).unwrap();
        let mut user = String::new();
        let mut pass = String::new();
        let mut uri = String::new();
        for line in data.unwrap().lines(){
            let s_line = line.trim().split("=").collect::<Vec<_>>();
            if s_line.get(0).unwrap() == &"user"{
                user = s_line[1..].join("=");
            } else if s_line.get(0).unwrap() == &"pass"{
                pass = s_line[1..].join("=");
            } else if s_line.get(0).unwrap() == &"server"{
                uri = s_line[1..].join("=");
            }
        }
        if user.is_empty() || pass.is_empty() || uri.is_empty(){
            eprintln!("error parsing one of the neo4j credential values, check
                your .bhdb file");
            return None;
        }
        Some(Neo4jConfig{
            user,uri,pass
        })
    }
}

#[derive(Debug)]
pub struct Principal {
    domain: String,
    user: String,
    password: Option<String>,
    ntlm: Option<String>,
}

impl Principal { 
    pub fn get_principal(&self)->String{
        format!("{}@{}",self.user,self.domain)
    }
    pub fn get_cred(&self)->Option<String>{
        if let Some(pass) = &self.password {
            return Some(pass.to_owned());
        } else if let Some(hash) = &self.ntlm {
            return Some(hash.to_owned());
        }
        None
    }

    pub fn get_impacket_format(&self)->String{
        let imp_string = format!("{}/{}",self.domain,self.user);
        let stub = String::from("");
        if let Some(pass) = &self.password {
            return format!("{}:{}",imp_string,pass)
        } else if let Some(hash) = &self.ntlm {
            return format!(" -hashes {} {}", hash,imp_string);
        }
        imp_string
    }

    pub fn format_cred(&self,cred: String)->String{
        match cred.trim().len() {
            65 => { // it's a hash
                return format!("-hashes {} {}/{}@",cred,self.domain,self.user);
            }
            0=>{ // empty cred provided
                return format!("{}/{}@",self.domain,self.user);
            }
            _=>{
                return format!("{}/{}:{}@",self.domain,self.user,cred);
            }
        }
    }

    pub fn set_domain(&mut self, domain: String) {
        self.domain = domain.to_uppercase();
    }

    pub fn from(line: String,domain:&Option<String>)->Option<Self>{
        let mut princ = None;
        if hashcat_format.is_match(&line){
            dprintln!("hashcat -> {:#?}",line);
            let mat = hashcat_format.find(&line).unwrap();
            princ = Principal::parse_hashcat_line(
                // knocking off the last three colons now
                line.get(mat.start()..mat.end()-3).unwrap().to_string()
            );
        } else if userprinc_format.is_match(&line){
            dprintln!("userprinc_format -> {:#?}",line);
            let mat = userprinc_format.find(&line).unwrap();
            princ = Principal::parse_userprinc_line(
                line.get(mat.start()..mat.end()).unwrap().to_string()
            );
        } else if secrets_format.is_match(&line){
            dprintln!("secrets_format -> {:#?}",line);
            let mat = secrets_format.find(&line).unwrap();
            princ = Principal::parse_secrets_line(
                line.get(mat.start()..mat.end()).unwrap().to_string()
            );
        } else if just_user_princ_format.is_match(&line){
            dprintln!("just_user_princ_format -> {:#?}",line);
            let mat = just_user_princ_format.find(&line).unwrap();
            princ = Principal::parse_just_user_princ_line(
                line.get(mat.start()..mat.end()).unwrap().to_string()
            );
        }

        if let Some(mut princv) = princ {
            if let Some(d_name) = domain {
                princv.set_domain(d_name.to_string());
                return Some(princv);
            }
            return Some(princv)
        }

        None
    }

    /// parses the 'standard' hashcat format into a Principal object
    fn parse_hashcat_line(line: String)->Option<Principal>{
        dprintln!("parsing hashcat line: {}",line);
        let lines = line.split(":").collect::<Vec<_>>();
        if lines.len() != 4 {
            eprintln!("error while parsing hashcat line: {}",&line);
            return None;
        }
        let s_one = lines.get(0).unwrap().split("\\").collect::<Vec<_>>();
        if s_one.len() != 2 {
            eprintln!("error while parsing hashcat user line from: {}",&line);
            return None;
        }

        dprintln!("{:?}",lines);
        return Some(Principal {
            domain: s_one.get(0).unwrap().to_string().to_uppercase(),
            user: s_one.get(1).unwrap().to_string().to_uppercase(),
            password: None,
            ntlm: Some(format!("{}:{}",lines.get(2).unwrap(),lines.get(3).unwrap())),
        })
    }
    /// parses user and domain from 'user@domain' format
    fn parse_just_user_princ_line(line: String)->Option<Principal>{
        dprintln!("parsing just_user");
        let s_line = line.split("@").collect::<Vec<_>>();
        if s_line.len()!=2{
            eprintln!("error parsing just_user_princ:invalid slice len:{}",line);
            return None;
        }
        Some(Principal{
            domain:s_line.get(1).unwrap().to_uppercase(),
            user:s_line.get(0).unwrap().to_uppercase(),
            ntlm:None,
            password:None
        })
    }
    /// parses user principal lines with :passwords suffixes
    fn parse_userprinc_line(line: String)->Option<Principal>{
        dprintln!("parsing userprinc (with pass)");
        let s_line = line.split("@").collect::<Vec<_>>();
        if s_line.len()<2{
            eprintln!("error parsing userprinc_line0:invalid slice len:{}",line);
            return None;
        }

        // parse user and domain
        let user = s_line.get(0).unwrap().to_uppercase();
        let mut dp_s_line = s_line.get(1).unwrap().split(":").collect::<Vec<_>>();
        let domain = dp_s_line.get(0).unwrap();

        // parse the password out
        let mut up_s_line = line.split(":").collect::<Vec<_>>();
        if up_s_line.len()<2{
            eprintln!("error parsing password from \
                      userprinc_line:invalid slice len:{}",line);
            return None;
        }
        up_s_line.remove(0);
        let pass = up_s_line.join(":");

        Some(Principal{
            domain:domain.to_string().to_uppercase(),
            user: user.to_string().to_uppercase(),
            ntlm:None,
            password:Some(pass),
        })

    }
    /// parses lines returned by LSA secrets plaintext creds
    fn parse_secrets_line(line: String)->Option<Principal>{
        dprintln!("parsing secrets");
        let mut domain = String::new();
        let mut user = String::new();

        let mut some_slice = line.split(":").collect::<Vec<_>>();
        let user_domain_slice = some_slice.remove(0);
        let pass = some_slice.join(":");
        if user_domain_slice.contains("\\") {
            some_slice = user_domain_slice.split("\\").collect::<Vec<_>>();
            // this one... just in case impacket command gets included in output
        } else if user_domain_slice.contains("/") {
            some_slice = user_domain_slice.split("/").collect::<Vec<_>>(); 
        } else {
            eprintln!("couldn't parse user/domain from slice: {}",
                      user_domain_slice);
            return None;
        }
        if some_slice.len()!=2{
            eprintln!("couldn't parse user/domain from sub slice: {:?}",
                      some_slice);
            return None;
        }
        domain = some_slice.get(0).unwrap().to_string().to_uppercase();
        user = some_slice.get(1).unwrap().to_string().to_uppercase();
        return Some(Principal {
            user,
            domain,
            ntlm: None,
            password: Some(pass),
        });
    }

}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_principal())
    }
}
