use std::fs;
use neo4rs::*;
use std::sync::Arc;
use structopt::StructOpt;
pub use regex::Regex;
pub use lazy_static::lazy_static;
mod utils;
pub use utils::*;

mod config;
pub use config::*;

#[derive(Debug,StructOpt)]
#[structopt(name="bh",author="deadjakk",about="Pentesting workflow optimizer that works with the bloodhound NEO4J db & schema")]
struct Opt{
    #[structopt(short,long)]
    /// mark user or list of users as owned
    markowned: bool,

    #[structopt(short,long)]
    /// dump credentials as well as the principal name (only used with -g)
    cred_dump: bool,

    #[structopt(short,long)]
    /// force a domain value for parsing, good if you're importing things from
    /// that might use an older name or a NETBIOS name for the domain
    domain: Option<String>,

    #[structopt(short,long)]
    /// get a list of computers to which the provided principal(s) have local
    /// administrators rights, passwords will be retrieved automagically in 
    /// impacket format if present in database in impacket format
    getadmins: bool,
    
    /// newline-separated file containing a list of principals or 
    /// principals+passwords see --help for more info and example formats... 
    /// any parsed passwords will be viewable in the bloodhound GUI when marking
    /// principals as owned
    ///
    ///
    /// the following formats are accepted (invalid lines are ignored):
    ///
    /// optionaldomain\user:password 
    ///
    /// optionaldomain/user:password 
    ///
    /// user@domain.com:password
    ///
    /// domain\user:RID:hash::: (hashcat format)
    ///
    /// user:RID:hash:::        (hashcat format)
    /// 
    /// some common output you might use here is 
    /// output from secretsdump.py (secrets/sam/or ntds.dit) 
    /// (hashcat format)
    ///
    /// output file or any hashcat format file
    /// to import passwords during the owned
    principals: String,
}

/// marks the provided principal as owned
async fn mark_owned(graph: Arc<Graph>,principal :Principal) {
     let mut f_query = query("MATCH (n{name:$name}) SET n.owned=true return n.owned ")
         .param("name", principal.get_principal().to_owned());
       if let Some(cred) = principal.get_cred(){
           f_query =  query("MATCH (n{name:$name}) SET n.owned=true SET n.cred = $cred return n.owned ")
             .param("name", principal.get_principal().to_owned())  
             .param("cred",cred);
       }
   let mut result = graph.execute(
       f_query
       ).await.unwrap();
   let mut worked = false;
   if let Ok(Some(row)) = result.next().await {
       if let Some(true) = row.get::<bool>("n.owned"){
           worked = true;
       }
   } 
   println!("marked {} as owned: {}",&principal,worked);
}

/// determines if the provided principals argument was supposed to represent
/// a principal itself, or a list of them.
fn get_principals(provided:&str,domain: Option<String>)->Vec<Principal>{
   // determine if a file was provided by check if the file exists
   let mut principals = Vec::new();
   let princ_file = fs::read_to_string(std::path::Path::new(provided));
   if let Ok(princ_lines) = princ_file{
       println!("found user file: {}",provided);
       for line in princ_lines.lines(){
           if let Some(princ) = Principal::from(line.to_string(),&domain){
               dprintln!("parsed: {:?}",&princ);
               principals.push(princ);
           }
       }
   } else {
       // must have just been a string
       if let Some(princ) = Principal::from(provided.to_string(),&domain){
           principals.push(princ);
       }
   }
   return principals;
}

/// yields the list of computers to which the provided principal has localadmin
/// rights. output is formatted to match that expected by impacket, containing
/// creds if present in the neo4j database.
async fn get_local_admins_with_creds(graph: Arc<Graph>,principal: Principal) {
    // separator in case multiple principals are being checked
    println!("-------- {} --------",&principal.get_principal());
    let mut result = graph.execute(
        // grouplocaladmin rights
        query("MATCH princ=(m:User {name:$name})-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN princ")
        .param("name", principal.get_principal().to_owned())  
        ).await.unwrap();
    while let Ok(Some(row)) = result.next().await {
        let mut output = String::from("");
        let r_row = row.get::<Path>("princ").unwrap().nodes();
        let name = r_row.last().unwrap().get::<String>("name").unwrap();
        let cred = r_row.first().unwrap().get::<String>("cred");
        if let Some(cred_str) = cred {
            output = principal.format_cred(cred_str);
        } 
        println!("{}{}",output,name);
    }
    let mut result = graph.execute(
        // grouplocaladmin rights
        query("MATCH comp=(m:User {name:$name})-[r:AdminTo]->(n:Computer) RETURN comp")
        .param("name", principal.get_principal().to_owned())  
        ).await.unwrap();
    while let Ok(Some(row)) = result.next().await {
        let mut output = String::from("");
        let r_row = row.get::<Path>("princ").unwrap().nodes();
        let name = r_row.last().unwrap().get::<String>("name").unwrap();
        let cred = r_row.first().unwrap().get::<String>("cred");
        if let Some(cred_str) = cred {
            output = principal.format_cred(cred_str);
        } 
    }
}

/// yields the list of computers to which the provided principal has localadmin
/// rights.
async fn get_local_admins(graph: Arc<Graph>,principal: Principal) {
    // separator in case multiple principals are being checked
    println!("-------- {} --------",&principal.get_principal());
    let mut result = graph.execute(
        query("MATCH princ=(m:User {name:$name})-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN princ")
        .param("name", principal.get_principal().to_owned())  
        ).await.unwrap();
    while let Ok(Some(row)) = result.next().await {
        let r_row = row.get::<Path>("princ").unwrap().nodes();
        let name = r_row.last().unwrap().get::<String>("name").unwrap();
        println!("{}",name);
    }
    let mut result = graph.execute(
        query("MATCH comp=(m:User {name:$name})-[r:AdminTo]->(n:Computer) RETURN comp")
        .param("name", principal.get_principal().to_owned())  
        ).await.unwrap();
    while let Ok(Some(row)) = result.next().await {
        let r_row = row.get::<Path>("princ").unwrap().nodes();
        let name = r_row.last().unwrap().get::<String>("name").unwrap();
        println!("{}",name);
    }
}

#[tokio::main]
async fn main() {
   let args= Opt::from_args();
   let creds = Neo4jConfig::get_creds().unwrap();
   dprintln!("{:?}",creds);

   // connect to db
   let graph = Arc::new(Graph::new(&creds.uri, &creds.user, &creds.pass).await.unwrap());
   let mut handles = Vec::new();

   // just determines if a string was provided, or a file
   let principals: Vec<Principal> = get_principals(&args.principals,args.domain);

   if args.markowned {
       for principal in principals {
           let graph_rc = graph.clone();
           let handle = tokio::spawn(async move {
               mark_owned(graph_rc,principal).await;
           }); handles.push(handle);
       }
   } else if args.getadmins {
       for principal in principals {
           // this needs not be threaded, will clobber results
           // unless we prepend every result (line) with provided principal
           // but seems kind of unecessary unless some automation
           // system needs that kind of speed
           let graph_rc = graph.clone();
           if args.cred_dump {
               get_local_admins_with_creds(graph_rc,principal).await;
               return
           }
           get_local_admins(graph_rc,principal).await;
       }
   } else {
       eprintln!("no command was provided");
   }

   futures::future::join_all(handles).await;
}
