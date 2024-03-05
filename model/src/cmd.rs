use crate::model::Cmd;

pub trait MapStr: Sized {
    fn from_str(s: String) -> Result<Self, ()>;
}

impl MapStr for Cmd {
    fn from_str(s: String) -> Result<Self, ()> {
        match s.to_lowercase().as_str() {
            "cat" => Ok(Cmd::Cat),
            "cd" => Ok(Cmd::Cd),
            "echo" => Ok(Cmd::Echo),
            "ls" => Ok(Cmd::Ls),
            "mkdir" => Ok(Cmd::Mkdir),
            "mv" => Ok(Cmd::Mv),
            "new" => Ok(Cmd::New),
            "pwd" => Ok(Cmd::Pwd),
            "touch" => Ok(Cmd::Touch),
            _ => Err(()),
        }
    }
}