#![allow(clippy::print_literal)]
#![allow(clippy::needless_return)]
#![allow(dropping_references)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::partialeq_to_none)]
use log::*;
use std::backtrace::*;
//use std::error::*;
//use std::path::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::*;
use std::*;

//list of commands:
//note all search/filter are done on top of previous search/filter to refine result list
// help (show help msg)
// /{keyword} (search ALL text and list matching rows.)
// ?{keyword (just like /, but case-sensitive)
// reset (discard all found rows)
// l (list found rows, maybe with pagination.)
// {number} (selecting a row among the listed rows) //NOTE this is not accumulative, so you type 3, and ENTER, and 4, and ENTER, then you have selected just one row (4), not two rows
//NOTE if filtering makes the list contain only one row, then the row is automatically selected, so no need to manually type {number} to select it

//todo
// u undo-filtering
// r redo-filtering
// register reg_name (save current list to a in-memory register, and then start over with a fresh empty list)
// specify arbitrary order for row(s)
//todo
// :v/{keyword} (search those not containing keyword)
//todo
// "{column_name}" [new_value] (Usually "" is optional. This sets value for a column (column must already exists in table), or just show value if no new_value. If column_name is the same as a command name, then the column has priority (but there are exceptions, e.g. DIRECT CMD or l). If column_name contains space you have to use "". If column_name contains double quote then you have to use r#""# or r##""## or even more #s. This is a little bit similar to Rust raw string literals)
// "{column_name}" [new_value] (Under DIRECT CMD mode, this has different meaning. It creates a new column (not existing before) and sets value for it for selected row. When new_value is absent it deletes a column for selected row)
//NOTE column_name can be partial in normal mode, as long as it partially matches just one column
//NOTE column names ending with :unique will have to conform to unique constraint
// see "{column_name}" (from now on, searching only applies on column_name. If column_name is not provided, then clear previously set `see` parameter)
// :se (list all config/parameter/etc.)
// :f (show path and info of the file(s) being edited)
// :his (show all history commands you typed)
//todo
// :checkt (chk if the file is changed since your last read)
// sync (firstly, do :w, and if using git, then run git pull and then git commit and then git push)
// new (add an empty row, and this row becomes the currently selected row)
// rm/- (remove selected rows from listed rows)
// rm/- {number} (remove a row from listed rows)
// dd/:del (delete selected row from table) //todo add feature of selecting multiple rows and deleting multiple rows
// :w (write to local file right now)
// exit/quit/CTRL-D (sync and then quit. If sync fails it will not quit)
// :e (open file in a text editor)
// cat (print raw content of file)
// **input nothing** (toggle to DIRECT CMD mode or toggle back. Under DIRECT CMD mode, only cmds are recognized, column_name is not recognized)
// gitdiff (show git diff)
//todo
// gitdiffwindow (run alacritty to show `git diff`)

//todo// parameters:
//auto_upload=disabled
//fileformat=tsv

//enum SyncStatus {
//	InSync,
//}

//CODE below is imitating example on https://docs.rs/aes-gcm/
fn encrypt_data(indata: &[u8]) -> Result<(), CustomErr> {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        Aes256Gcm,
        Nonce, // Or `Aes128Gcm`
    };

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message//fixme need to be unique
    let ciphertext = cipher.encrypt(nonce, indata)?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    assert_eq!(&plaintext, indata);
    return Ok(());
}
//todo
//fn encrypt_json
//https://security.stackexchange.com/questions/38828/how-can-i-securely-convert-a-string-password-to-a-key-used-in-aes
#[derive(Serialize, Deserialize, Default)]
struct EncryptedJson {
    key_for_data_encryption: String,
    pw_hashed_twice: String,
    nonce: String,
    ciphertext: String,
}

//impl EncryptedJson {
//	fn decrypt (&self) {
//	}
//}

#[derive(Clone, Debug, Default, PartialEq)]
struct Ctx {
    envargs: Vec<String>, //note vec default will not allocate
    canonicalized: PathBuf,
    parent_dir: PathBuf,
    sync_method: &'static str,
    mem_in_sync_with_local: bool,
    local_in_sync_with_remote: bool,
    direct_cmd_mode: bool,
    tbl: Tbl,
    linestr: String,
    already_checked_git_email_n_name: bool,
}

impl Ctx {
    pub fn new(args: Vec<String>) -> Self {
        Ctx {
            mem_in_sync_with_local: true,
            envargs: args,
            ..Default::default()
        }
    }
    fn init(&mut self) -> Result<(), CustomErr> {
        //debug
        dbg!(self.filenm());

        self.canonicalized = fs::canonicalize(self.filenm())?;
        if !self.canonicalized.is_file() {
            error!("{}", "Path is not a file.");
            return Err(CustomErr {});
        }
        let parent_val = self
            .canonicalized
            .parent()
            .ok_or("Failed to get the folder containing the file.")?;
        if !parent_val.is_dir() {
            error!("{}", "Failed to recognize the folder containing the file.");
            return Err(CustomErr {});
        }
        self.parent_dir = parent_val.to_path_buf();
        //debug
        println!("{:?}", self.canonicalized);
        println!("{:?}", self.parent_dir);
        let env_var_sync_method = env::var("FLATFILETABLE_SYNC_METHOD");
        match env_var_sync_method {
            Ok(smstr) => {
                sync_method_verify_and_init(self, smstr)?;
            }
            Err(err) => {
                if std::env::VarError::NotPresent != err {
                    error!("{}\n{}", err, Backtrace::force_capture());
                    return Err(CustomErr {});
                }
            }
        }
        return Ok(());
    }
    fn filenm(&self) -> &str {
        &self.envargs[1]
    }
    //fn get_dir_of_file(&self) {
    //    let _ddd = Path::new(self.filenm());
    //}
    fn printlisted(&self) {
        let mut idx_dis = 0;
        for (idx, row) in self.tbl.rows.iter().enumerate() {
            match &self.tbl.selected[idx] {
                RowSel::Not => {
                    continue;
                }
                RowSel::Listed => {
                    print!("{}", " ");
                }
                RowSel::Selected => {
                    print!("{}", "+");
                }
            }
            println!(" {} {:?}", idx_dis, row);
            idx_dis += 1;
        }
        if 0 == idx_dis {
            println!("{}", "Nothing to list");
        }
    }
    fn set_single_listed_to_sel(&mut self) {
        for rowsel in &mut self.tbl.selected {
            if RowSel::Listed == *rowsel {
                *rowsel = RowSel::Selected;
                break;
            }
        }
    }
    fn filter_with_slash(&mut self) {
        let fstr = &self.linestr[1..];
        let mut cloned_selection = self.tbl.selected.clone();
        let mut idx_dis = 0;
        let mut any_listed = false;
        'search_listed: for (idx, row) in self.tbl.rows.iter().enumerate() {
            match &cloned_selection[idx] {
                RowSel::Not => {
                    continue;
                }
                RowSel::Listed => {}
                RowSel::Selected => {}
            }
            any_listed = true;
            for (_entkey, entval) in row {
                if entval.to_ascii_lowercase().contains(fstr) {
                    idx_dis += 1;
                    continue 'search_listed;
                }
            }
            cloned_selection[idx] = RowSel::Not;
        }
        if any_listed {
            if 0 == idx_dis {
                println!("{}", "Unable to apply this filter because no row matches");
                return;
            } else {
                self.tbl.selected = cloned_selection;
            }
        } else {
            for (idx, row) in self.tbl.rows.iter().enumerate() {
                for (_entkey, entval) in row {
                    if entval.to_ascii_lowercase().contains(fstr) {
                        idx_dis += 1;
                        self.tbl.selected[idx] = RowSel::Listed;
                        break;
                    }
                }
            }
        }
        if 1 == idx_dis {
            self.set_single_listed_to_sel();
        }
        self.printlisted();
    }
    fn confirm_with_user_if_col_match(&mut self) -> bool {
        if self.direct_cmd_mode {
            return false;
        }
        let splitted = self.linestr.split_once(' ');
        let col: &str;
        let rest: &str;
        match splitted {
            None => {
                col = self.linestr.as_str();
                rest = "";
            }
            Some((s_col, s_rest)) => {
                col = s_col;
                rest = s_rest;
            }
        }
        if !self.tbl.all_columns.contains(col) {
            return false;
        }
        println!("{}", "Found column name matching your input. So it is treated as column name instead of command name.");
        _ = normal_mode_proc_col(&mut self.tbl, col, rest, None == splitted);
        return true;
    }
    fn columns(&self) {
        println!("{:?}", self.tbl.all_columns);
        //todo also print total number of occurrence of each column name?
    }
}
fn normal_mode_proc_col(
    tbl: &mut Tbl,
    col: &str,
    rest: &str,
    bare_col: bool,
) -> Result<(), CustomErr> {
    let ridx = tbl.get_selected_single_row_idx();
    if -1 == ridx {
        println!("{}", "No row selected.");
        return Ok(());
    }
    if bare_col {
        println!("FIELD {:?}", tbl.rows[ridx as usize].get(col));
        return Ok(());
    }
    //note if col is :unique AND new_value == old_value, then it triggers constraint violation here (maybe you should change the warning message from constraint violation to something like "Value is the same as old"?)
    update_possible_unique_constraint_addition(tbl, col, rest)?;
    update_possible_col_addition(tbl, col);
    let old = tbl.rows[ridx as usize].insert(col.to_owned(), rest.to_owned());
    println!("FIELD UPDATED {:?}", tbl.rows[ridx as usize].get(col));
    if let Some(old_v) = old {
        update_possible_unique_constraint_removal(tbl, col, old_v);
    }
    return Ok(());
}
fn direct_cmd_mode_proc_col(
    tbl: &mut Tbl,
    col: &str,
    rest: &str,
    bare_col: bool,
) -> Result<(), CustomErr> {
    let ridx = tbl.get_selected_single_row_idx();
    if -1 == ridx {
        println!("{}", "No row selected.");
        return Ok(());
    }
    if bare_col {
        let refrow = &mut tbl.rows[ridx as usize];
        let old = refrow.remove(col);
        println!("FIELD REMOVED {:?}", refrow);
        if let Some(old_v) = old {
            update_possible_col_removal(tbl, col); //must be first
            update_possible_unique_constraint_removal(tbl, col, old_v); //must be second
        }
        return Ok(());
    }
    if tbl.rows[ridx as usize].contains_key(col) {
        println!(
            "{}",
            "Cannot add new field because it already exists in the row."
        );
        return Ok(());
    }
    update_possible_unique_constraint_addition(tbl, col, rest)?;
    update_possible_col_addition(tbl, col);
    let refrow = &mut tbl.rows[ridx as usize];
    refrow.insert(col.to_owned(), rest.to_owned());
    println!("FIELD ADDED {:?}", refrow);
    return Ok(());
}
fn update_possible_unique_constraint_removal(tbl: &mut Tbl, col: &str, old_v: String) {
    if !col.ends_with(":unique") {
        return;
    }
    let u8sli = &col.as_bytes()[0..col.len() - ":unique".len()];
    if !tbl.all_columns.contains(col) {
        tbl.constraint_unique.remove(u8sli);
        return;
    }
    for row in &tbl.rows {
        if let Some(vstr) = row.get(col) {
            if vstr == &old_v {
                return;
            }
        }
    }
    let get_res: Option<&mut HashSet<String>> = tbl.constraint_unique.get_mut(u8sli);
    get_res.unwrap().remove(&old_v);
}
fn update_possible_col_removal(tbl: &mut Tbl, col: &str) {
    for row in &tbl.rows {
        if row.contains_key(col) {
            return;
        }
    }
    tbl.all_columns.remove(col);
}
fn update_possible_unique_constraint_addition(
    tbl: &mut Tbl,
    col: &str,
    rest: &str,
) -> Result<(), CustomErr> {
    if !col.ends_with(":unique") {
        return Ok(());
    }
    let u8sli = &col.as_bytes()[0..col.len() - ":unique".len()];
    let get_res: Option<&mut HashSet<String>> = tbl.constraint_unique.get_mut(u8sli);
    match get_res {
        None => {
            let mut new_set: HashSet<String> = HashSet::new();
            new_set.insert(rest.to_owned());
            tbl.constraint_unique.insert(u8sli.to_owned(), new_set);
        }
        Some(uniq_set) => {
            if !uniq_set.insert(rest.to_owned()) {
                error!("{}", "Unique contraint is violated");
                return Err(CustomErr {});
            }
        }
    }
    return Ok(());
}
fn update_possible_col_addition(tbl: &mut Tbl, col: &str) {
    tbl.all_columns.insert(col.to_owned());
}

fn sync_method_verify_and_init(ctx: &mut Ctx, the_method: String) -> Result<(), CustomErr> {
    match the_method.as_str() {
        "" => {}
        "git" => {
            ctx.sync_method = "git";
        }
        _ => {
            error!("{}", "Sync Method is not supported");
            return Err(CustomErr {});
        }
    }
    return Ok(());
}

fn sync2remote(ctx: &mut Ctx) -> bool {
    //optimize use function pointer is better?
    match ctx.sync_method {
        "" => {
            return true;
        }
        "git" => {
            return sync_via_git(ctx);
        }
        _ => {
            error!("{}", "Sync Method is not supported");
            return false;
        }
    }
}

fn sync_via_git(ctx: &mut Ctx) -> bool {
    'gitcmd: {
        println!("{}", "****** GIT PULL ******");
        match Command::new("git")
            .current_dir(&ctx.parent_dir)
            .arg("pull")
            .output()
        {
            Err(err) => {
                error!("{}\n{}", err, Backtrace::force_capture());
                return false;
            }
            Ok(out) => {
                println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
                println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
                if !out.status.success() {
                    error!("{}", "git exit status is not successful",);
                    return false;
                }
            }
        }
        println!("{}", "****** GIT ADD ******");
        match Command::new("git")
            .current_dir(&ctx.parent_dir)
            .arg("add")
            .arg("-u")
            .output()
        {
            Err(err) => {
                error!("{}\n{}", err, Backtrace::force_capture());
                return false;
            }
            Ok(out) => {
                println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
                println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
                if !out.status.success() {
                    error!("{}", "git exit status is not successful",);
                    return false;
                }
            }
        }
        println!("{}", "****** GIT DIFF ******");
        match Command::new("git")
            .current_dir(&ctx.parent_dir)
            .arg("diff")
            .arg("--cached")
            //.arg("--name-only")
            .output()
        {
            Err(err) => {
                error!("{}\n{}", err, Backtrace::force_capture());
                return false;
            }
            Ok(out) => {
                println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
                println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
                if !out.status.success() {
                    error!("{}", "git exit status is not successful",);
                    return false;
                }
                if out.stdout.is_empty() {
                    //println!("{}", SYNC_DONE_STR);
                    //return true;
                    break 'gitcmd;
                }
            }
        }
        if !ctx.already_checked_git_email_n_name {
            ctx.already_checked_git_email_n_name = true;
            if git_chk_email_n_name(ctx).is_err() {
                return false;
            }
        }
        println!("{}", "****** GIT COMMIT ******");
        match Command::new("git")
            .current_dir(&ctx.parent_dir)
            .arg("commit")
            .arg("--allow-empty-message")
            .arg("-m")
            .arg("")
            .output()
        {
            Err(err) => {
                error!("{}\n{}", err, Backtrace::force_capture());
                return false;
            }
            Ok(out) => {
                println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
                println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
                if !out.status.success() {
                    error!("{}", "git exit status is not successful",);
                    return false;
                }
            }
        }
        println!("{}", "****** GIT PUSH ******");
        match Command::new("git")
            .current_dir(&ctx.parent_dir)
            .arg("push")
            .arg("-u")
            .arg("origin")
            .arg("HEAD") //https://stackoverflow.com/questions/23241052/what-does-git-push-origin-head-mean
            .output()
        {
            Err(err) => {
                error!("{}\n{}", err, Backtrace::force_capture());
                return false;
            }
            Ok(out) => {
                println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
                println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
                if !out.status.success() {
                    error!("{}", "git exit status is not successful",);
                    return false;
                }
            }
        }
    }
    ctx.local_in_sync_with_remote = true;
    const SYNC_DONE_STR: &str = "****** SYNC DONE ******";
    println!("{}", SYNC_DONE_STR);
    return true;
}

fn git_chk_email_n_name(ctx: &Ctx) -> Result<(), CustomSimpleErr> {
    println!("{}", "****** GIT CHK ******");
    let out = Command::new("git")
        .current_dir(&ctx.parent_dir)
        .arg("config")
        .arg("user.email")
        .output()?;
    println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
    println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
    if out.stdout.is_empty() {
        error!("{}", "git output is empty",);
        return Err(CustomSimpleErr {});
    }
    if !out.status.success() {
        error!("{}", "git exit status is not successful",);
        return Err(CustomSimpleErr {});
    }
    let out = Command::new("git")
        .current_dir(&ctx.parent_dir)
        .arg("config")
        .arg("user.name")
        .output()?;
    println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
    println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
    if out.stdout.is_empty() {
        error!("{}", "git output is empty",);
        return Err(CustomSimpleErr {});
    }
    if !out.status.success() {
        error!("{}", "git exit status is not successful",);
        return Err(CustomSimpleErr {});
    }
    println!("{}", "****** GIT CHK DONE ******");
    return Ok(());
}

fn gitdiff(ctx: &Ctx) -> Result<(), CustomSimpleErr> {
    println!("{}", "****** GIT DIFF ******");
    let out = Command::new("git")
        .current_dir(&ctx.parent_dir)
        .arg("diff")
        .output()?;
    println!("STDOUT\n{}", String::from_utf8_lossy(&out.stdout));
    println!("STDERR\n{}", String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        error!("{}", "git exit status is not successful",);
        return Ok(()); //not serious enough to be treated as err
    }
    println!("{}", "****** GIT DIFF DONE ******");
    return Ok(());
}

struct CustomSimpleErr {}
impl<E: std::fmt::Display> From<E> for CustomSimpleErr {
    fn from(inner: E) -> Self {
        error!("{}", inner);
        Self {}
    }
}

//#[derive(Clone, Debug, Default, PartialEq)]
struct CustomErr {
    //inner: Error
}

impl<E: std::fmt::Display> From<E> for CustomErr {
    fn from(inner: E) -> Self {
        error!("{}\n{}", inner, Backtrace::force_capture());
        Self {}
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
enum RowSel {
    #[default]
    Not,
    Listed,
    Selected,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Tbl {
    rows: Vec<BTreeMap<String, String>>,
    //optimize no need to use constraint_unique and all_columns at the same time. They can be combined to one hashmap?
    constraint_unique: HashMap<Vec<u8>, HashSet<String>>,
    all_columns: HashSet<String>,
    selected: Vec<RowSel>,
}

impl Tbl {
    fn select_single_row(&mut self, rownum: usize) {
        let mut count: usize = 0;
        for rowsel in &mut self.selected {
            if RowSel::Not != *rowsel {
                if count == rownum {
                    *rowsel = RowSel::Selected;
                } else {
                    *rowsel = RowSel::Listed;
                }
                count += 1;
            }
        }
        //if rownum is too great, all rows are de-selected
    }
    fn get_selected_single_row_idx(&self) -> i32 {
        for (idx, rowsel) in self.selected.iter().enumerate() {
            if RowSel::Selected == *rowsel {
                return idx as i32;
            }
        }
        return -1;
    }
}

fn readjson(ctx: &mut Ctx) -> Result<(), CustomErr> {
    use std::fs::*;
    let file = File::open(&ctx.canonicalized)?;
    let reader = std::io::BufReader::new(file);
    let tbl: serde_json::Value = serde_json::from_reader(reader)?;
    use serde_json::Value::Array;
    use serde_json::Value::Object;
    let mut retval = Tbl::default();
    match tbl {
        Array(row_vec) => {
            for jsonrow in row_vec {
                match jsonrow {
                    Object(row_map) => {
                        let mut new_map: BTreeMap<String, String> = BTreeMap::new();
                        for (entkey, entval) in row_map {
                            retval.all_columns.insert(entkey.clone()); //optimize it is cloning even when insertion returns false?
                            match entval {
                                serde_json::Value::String(v_str) => {
                                    if entkey.ends_with(":unique") {
                                        let u8sli =
                                            &entkey.as_bytes()[0..entkey.len() - ":unique".len()];
                                        let get_res: Option<&mut HashSet<String>> =
                                            retval.constraint_unique.get_mut(u8sli);
                                        match get_res {
                                            None => {
                                                let mut new_set: HashSet<String> = HashSet::new();
                                                new_set.insert(v_str.clone());
                                                retval
                                                    .constraint_unique
                                                    .insert(u8sli.to_owned(), new_set);
                                            }
                                            Some(uniq_set) => {
                                                if !uniq_set.insert(v_str.clone()) {
                                                    error!("{}", "Unique contraint is violated");
                                                    return Err(CustomErr {});
                                                }
                                            }
                                        }
                                    }
                                    new_map.insert(entkey, v_str); //note JSON obj with duplicate field could be considered valid (though some people disagree) ECMA-404 says nothing but RFC uses wording of SHOULD
                                }
                                _ => {
                                    error!(
                                        "{}",
                                        "Types other than string are not supported in fields"
                                    );
                                    return Err(CustomErr {});
                                }
                            }
                        }
                        retval.rows.push(new_map);
                    }
                    _ => {
                        error!("{}", "Each row must be object");
                        return Err(CustomErr {});
                    }
                }
            }
        }
        //todo
        //Object(encobj) => {
        //		let mut encjson = EncryptedJson::default();
        //                for (entkey, entval) in encobj {
        //                    match entval {
        //                        serde_json::Value::String(v_str) => {
        //			    match entkey.as_str() {
        //				    "key_for_data_encryption"=>{
        //					encjson.key_for_data_encryption = v_str;
        //				    }
        //				    "pw_hashed_twice"=>{
        //					encjson.pw_hashed_twice = v_str;
        //				    }
        //				    "ciphertext"=>{
        //					encjson.ciphertext = v_str;
        //				    }
        //				    "nonce"=>{
        //					encjson.nonce = v_str;
        //				    }
        //				    _=>{
        //                            error!(
        //                                "{}",
        //                                "Unexpected field in encrypted json."
        //                            );
        //                            return Err(CustomErr {});
        //				    }
        //			    }
        //                        }
        //                        _ => {
        //                            error!(
        //                                "{}",
        //                                "Types other than string are not supported in fields"
        //                            );
        //                            return Err(CustomErr {});
        //                        }
        //                    }
        //		}
        //}
        _ => {
            error!("{}", "Whole JSON must be array or obj");
            return Err(CustomErr {});
        }
    }
    //match File::open(ctx.canonicalized) {
    //	Err(err)=>{
    //        	error!("{}\n{}", err, Backtrace::force_capture());
    //		return false;
    //	}
    //	Ok(file)=>{
    //	}
    //}
    retval.selected = vec![RowSel::Not; retval.rows.len()];
    ctx.tbl = retval;
    return Ok(());
}

#[macro_use(defer)]
extern crate scopeguard;

fn main() -> ExitCode {
    env::set_var("RUST_BACKTRACE", "1"); //? not 100% sure this has 0 impact on performance? Maybe setting via command line instead of hardcoding is better?
                                         //env::set_var("RUST_LIB_BACKTRACE", "1");//? this line is useless?
                                         ////
    env::set_var("RUST_LOG", "trace"); //note this line must be above logger init.
    env_logger::init();
    ////
    //const PKG_NAME: &str = env!("CARGO_PKG_NAME");
    //env::set_var("DEBUG_CPN", PKG_NAME);

    //todo first arg as file to open, if not specified, list recent files for selection
    let args: Vec<String> = env::args().collect(); //Note that std::env::args will panic if any argument contains invalid Unicode.
    defer! {
        println!("{}", "ALL DONE");
    }
    if 2 != args.len() {
        if 2 < args.len() {
            error!("{}", "Too many args");
        } else {
            error!("{}", "Too few args");
        }
        return ExitCode::from(1);
    }
    let currworkingdir = env::current_dir();
    match currworkingdir {
        Ok(val) => {
            println!("CWD is {:?}", val);
        }
        Err(err) => {
            error!("{}\n{}", err, Backtrace::force_capture());
            return ExitCode::from(1);
        }
    }

    let mut ctx = Ctx::new(args);
    if ctx.init().is_err() {
        return ExitCode::from(1);
    }
    if !sync2remote(&mut ctx) {
        return ExitCode::from(1);
    }
    if readjson(&mut ctx).is_err() {
        return ExitCode::from(1);
    }
    println!("{} ROWS READ", ctx.tbl.rows.len());
    let stdin = io::stdin();
    use std::io::prelude::*;
    for line in stdin.lock().lines() {
        let typed_l: Result<std::string::String, std::io::Error> = line;
        match typed_l {
            Err(err) => {
                error!("{}\n{}", err, Backtrace::force_capture());
                return ExitCode::from(1);
            }
            Ok(linestr) => {
                ctx.linestr = linestr;
                let cmd_res = parse_input_line(&mut ctx);
                match cmd_res {
                    Err(_) => {
                        return ExitCode::from(1);
                    }
                    Ok(continue_lo) => {
                        if !continue_lo {
                            break;
                        }
                    }
                }
            }
        }
    }
    if writejson(&ctx).is_err() {
        return ExitCode::from(1);
    }
    if !sync2remote(&mut ctx) {
        return ExitCode::from(1);
    }
    //debug
    //println!("{}", serde_json::to_string_pretty(&ctx.tbl.rows).unwrap());
    //
    return ExitCode::from(0);
}
fn writejson(ctx: &Ctx) -> Result<(), CustomErr> {
    use std::fs::*;
    let mut file = File::create(&ctx.canonicalized)?;
    serde_json::to_writer_pretty(&file, &ctx.tbl.rows)?;
    use std::io::prelude::*;
    file.write_all(b"\n")?;
    Ok(())
}

fn delblank(ctx: &mut Ctx) {
    let size_before = ctx.tbl.rows.len();
    ctx.tbl.rows.retain(|row| !row.is_empty());
    let size_after = ctx.tbl.rows.len();
    println!("{}{}", size_before - size_after, " ROWS REMOVED");
    ctx.tbl.selected.truncate(size_after);
    ctx.tbl.selected.fill(RowSel::Not);
}
fn del(ctx: &mut Ctx) {
    let tbl = &mut ctx.tbl;
    let ridx = tbl.get_selected_single_row_idx();
    if -1 == ridx {
        println!("{}", "No row selected.");
    }
    tbl.selected.remove(ridx as usize);
    let oldrow = tbl.rows.remove(ridx as usize);
    println!("{}", "ROW REMOVED");
    for (col, old_v) in oldrow {
        update_possible_col_removal(tbl, &col); //must be first
        update_possible_unique_constraint_removal(tbl, &col, old_v); //must be second
    }
}
fn proc_col(tbl: &mut Tbl, col: &str, rest: &str, bare_col: bool, direct_cmd_mode: bool) {
    if direct_cmd_mode {
        _ = direct_cmd_mode_proc_col(tbl, col, rest, bare_col);
    } else {
        let mut count: usize = 0;
        let mut colref = String::default();
        for colstr in &tbl.all_columns {
            if colstr.contains(col) {
                count += 1;
                println!("COL {}", colstr);
                colref = colstr.to_owned(); //optimize
            }
        }
        match count {
            0 => {
                println!("{}", "Column not found");
                return;
            }
            1 => {
                _ = normal_mode_proc_col(tbl, &colref, rest, bare_col);
            }
            _ => {
                println!("{}", "Too many matches");
                return;
            }
        }
    }
}
fn check_linestr_first_com_as_col_name(ctx: &mut Ctx) {
    if let Some(dqidx) = ctx.linestr.find('"') {
        if dqidx == 0 {
            let after_first_dq = &ctx.linestr.as_bytes()[1..];
            match after_first_dq.iter().position(|&ch| ch == b'"') {
                None => {
                    println!(
                        "{}",
                        "Invalid cmd. End of column name (double quote) is not found"
                    );
                    return;
                }
                Some(endidx) => {
                    let offset = endidx + 1;
                    if offset == after_first_dq.len() {
                        //debug
                        println!("{}", "raw literal col name (double quote) ends clearly");
                        proc_col(
                            &mut ctx.tbl,
                            &String::from_utf8_lossy(&after_first_dq[..endidx]),
                            "",
                            true,
                            ctx.direct_cmd_mode,
                        );
                        return;
                    } else if after_first_dq[offset] == b' ' {
                        //debug
                        println!("{}", "raw literal col name (double quote) ends with space");
                        proc_col(
                            &mut ctx.tbl,
                            &String::from_utf8_lossy(&after_first_dq[..endidx]),
                            &String::from_utf8_lossy(&after_first_dq[offset + 1..]),
                            false,
                            ctx.direct_cmd_mode,
                        );
                        return;
                    } else {
                        println!(
                            "{}",
                            "Invalid cmd. End of column name (double quote) at unexpected position"
                        );
                        return;
                    }
                }
            }
        } else if ctx.linestr.as_bytes().get(0) == Some(&b'r') {
            let pound = &ctx.linestr.as_bytes()[1..dqidx];
            if pound.iter().all(|&ch| ch == b'#') {
                let com_end: Vec<u8> = [br#"""#.as_slice(), pound].concat();
                let after_first_dq = &ctx.linestr.as_bytes()[dqidx + 1..];
                //note you can compare slice with ==
                let end_found = after_first_dq
                    .windows(com_end.len())
                    .position(|win| win == com_end);
                match end_found {
                    None => {
                        println!("{}", "Invalid cmd. End of column name is not found");
                        return;
                    }
                    Some(endidx) => {
                        let offset = endidx + com_end.len();
                        if offset == after_first_dq.len() {
                            //debug
                            println!("{}", "raw literal col name ends clearly");
                            proc_col(
                                &mut ctx.tbl,
                                &String::from_utf8_lossy(&after_first_dq[..endidx]),
                                "",
                                true,
                                ctx.direct_cmd_mode,
                            );
                            return;
                        } else if after_first_dq[offset] == b' ' {
                            //debug
                            println!("{}", "raw literal col name ends with space");
                            proc_col(
                                &mut ctx.tbl,
                                &String::from_utf8_lossy(&after_first_dq[..endidx]),
                                &String::from_utf8_lossy(&after_first_dq[offset + 1..]),
                                false,
                                ctx.direct_cmd_mode,
                            );
                            return;
                        } else {
                            println!(
                                "{}",
                                "Invalid cmd. End of column name at unexpected position"
                            );
                            return;
                        }
                    }
                }
            } else {
                check_linestr_plain_col_name(ctx);
            }
        } else {
            //double quote exists, but not at beginning or having r as beginning
            check_linestr_plain_col_name(ctx);
        }
    } else {
        //no double quote anywhere
        check_linestr_plain_col_name(ctx);
    }
}
fn check_linestr_plain_col_name(ctx: &mut Ctx) {
    let splitted = ctx.linestr.split_once(' ');
    match splitted {
        None => {
            proc_col(&mut ctx.tbl, &ctx.linestr, "", true, ctx.direct_cmd_mode);
        }
        Some((col, rest)) => {
            proc_col(&mut ctx.tbl, col, rest, false, ctx.direct_cmd_mode);
        }
    }
}
fn parse_input_line(ctx: &mut Ctx) -> Result<bool, CustomErr> {
    //for below, every cmd, you MUST check whether it collides with a column name! (EXCEPT those doing nothing significant, i.e. non-transactional, like "l")
    match ctx.linestr.as_str() {
        "" => {
            ctx.direct_cmd_mode = !ctx.direct_cmd_mode;
            if ctx.direct_cmd_mode {
                println!("{}", "You have entered DIRECT CMD mode");
            } else {
                println!("{}", "You have left DIRECT CMD mode");
            }
        }
        "l" => {
            //ignore column name collision
            ctx.printlisted();
        }
        "reset" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            ctx.tbl.selected.fill(RowSel::Not);
            println!("{}", "RESET");
        }
        "new" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            ctx.tbl.rows.push(BTreeMap::<String, String>::new());
            ctx.tbl.selected.fill(RowSel::Not);
            ctx.tbl.selected.push(RowSel::Selected);
            ctx.printlisted();
        }
        "del" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            del(ctx);
        }
        "exit" | "quit" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            return Ok(false);
        }
        "gitdiff" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            _ = gitdiff(ctx);
        }
        "columns" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            ctx.columns();
        }
        "delblank" => {
            if ctx.confirm_with_user_if_col_match() {
                return Ok(true);
            }
            delblank(ctx);
        }
        _ => match ctx.linestr.chars().next().unwrap() {
            '/' => {
                if ctx.confirm_with_user_if_col_match() {
                    return Ok(true);
                }
                ctx.linestr.make_ascii_lowercase();
                ctx.filter_with_slash();
            }
            '?' => {
                if ctx.confirm_with_user_if_col_match() {
                    return Ok(true);
                }
                println!("{}", "Not implemented"); //todo
            }
            _ => match ctx.linestr.parse::<usize>() {
                Err(_) => {
                    check_linestr_first_com_as_col_name(ctx);
                    return Ok(true);
                }
                Ok(idx) => {
                    //ignore column name collision
                    ctx.tbl.select_single_row(idx);
                    ctx.printlisted();
                    return Ok(true);
                }
            },
        },
    }
    return Ok(true);
}
