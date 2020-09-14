mod binding;
use std::collections::VecDeque;
use std::convert::From;
use std::error::Error;
use std::{convert::TryInto, fmt::Display};

pub type Result<T> = std::result::Result<T, DiagError>;

const TCP_ALL: u32 = 0xfff;

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn nlmsg_hdrlen() -> usize {
    nlmsg_align(std::mem::size_of::<libc::nlmsghdr>())
}

fn nlmsg_length(len: usize) -> usize {
    len + nlmsg_hdrlen()
}

#[derive(Debug)]
pub enum DiagError {
	NoMessagesError,
    NetLinkError(i32),
    OsError,
    ABIError,
}

impl Display for DiagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::io::Error> for DiagError {
    fn from(_: std::io::Error) -> Self {
        DiagError::OsError
    }
}

impl From<std::num::TryFromIntError> for DiagError {
    fn from(_: std::num::TryFromIntError) -> Self {
        DiagError::ABIError
    }
}

impl Error for DiagError {}

#[derive(Debug)]
pub enum DiagKind {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl DiagKind {
    fn family(&self) -> u8 {
        match self {
            DiagKind::Tcp | DiagKind::Udp => libc::AF_INET as u8,
            DiagKind::Tcp6 | DiagKind::Udp6 => libc::AF_INET6 as u8,
        }
    }

    fn proto(&self) -> u8 {
        match self {
            DiagKind::Tcp | DiagKind::Tcp6 => libc::IPPROTO_TCP as u8,
            DiagKind::Udp | DiagKind::Udp6 => libc::IPPROTO_UDP as u8,
        }
    }
}
#[derive(Debug)]
pub struct NetDiag {
    fd: i32,
    queue: VecDeque<SockInfo>,
    kind: DiagKind,
}

impl Drop for NetDiag {
    fn drop(&mut self) {
        self.queue.clear();
        unsafe { libc::close(self.fd) };
    }
}

impl NetDiag {
    pub fn new_tcp() -> Self {
        let fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_INET_DIAG) };
        NetDiag {
            fd,
            queue: VecDeque::new(),
            kind: DiagKind::Tcp,
        }
    }

    pub fn new_udp() -> Self {
        let fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_INET_DIAG) };
        NetDiag {
            fd,
            queue: VecDeque::new(),
            kind: DiagKind::Udp,
        }
    }

    fn get_messages(&mut self) -> Result<()> {
		send_diagmsg(self.fd, self.kind.family(), self.kind.proto())?;
        let page_size = std::cmp::min(unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize }, 8192);
        let mut buffer = Vec::<u32>::with_capacity(page_size);
        let buff_size = buffer.capacity();
        unsafe {
            buffer.set_len(buff_size);
        }
        let len = unsafe { libc::recv(self.fd, buffer.as_mut_ptr() as _, buff_size * 4, 0) };
        if len < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut header = buffer.as_ptr() as *const libc::nlmsghdr;
        let mut len = len as usize;
        loop {
            if len < nlmsg_hdrlen() {
                break;
            }
            let msg_len = unsafe { (*header).nlmsg_len } as usize;
            if len < msg_len {
                break;
            }
            let msg_type = unsafe { (*header).nlmsg_type } as u32;
            match msg_type {
                binding::NLMSG_NOOP => continue,
                binding::NLMSG_ERROR => {
                    let err = unsafe { parse_error(header) };
                    return Err(err);
                }
                _ => {
                    if let Some(sock_info) = unsafe { parse_msg(header) } {
                        self.queue.push_back(sock_info);
                    }
                }
            };
            // NLSMSG_NEXT
            let aligned_len = nlmsg_align(msg_len);
            header = (header as usize + aligned_len) as *const libc::nlmsghdr;
            match len.checked_sub(aligned_len) {
                Some(v) => len = v,
                None => break,
            };
        }
        Ok(())
    }

    pub fn recv(&mut self) -> Result<SockInfo> {
        if self.queue.is_empty() {
            self.get_messages()?;
		}
        self.queue.pop_front().ok_or(DiagError::NoMessagesError)
    }
}

unsafe fn parse_error(header: *const libc::nlmsghdr) -> DiagError {
    let err = (header as usize + nlmsg_length(0)) as *const libc::nlmsgerr;
    if ((*header).nlmsg_len as usize) < nlmsg_length(std::mem::size_of::<libc::nlmsgerr>()) {
        DiagError::NetLinkError(0)
    } else {
        DiagError::NetLinkError((*err).error)
    }
}

unsafe fn parse_msg(header: *const libc::nlmsghdr) -> Option<SockInfo> {
    let msg = (header as usize + nlmsg_length(0)) as *const binding::inet_diag_msg;
    if ((*msg).idiag_family as i32) != libc::AF_INET
        && ((*msg).idiag_family as i32) != libc::AF_INET6
    {
        return None;
    }
    let user_info = libc::getpwuid((*msg).idiag_uid);
    let uid = (*user_info).pw_uid;
    let inode = (*msg).idiag_inode;
    let srcport = (*msg).id.idiag_sport.to_be(); // ntohs
    let dstport = (*msg).id.idiag_dport.to_be();
    let src = (*msg).id.idiag_src.to_vec();
    let dst = (*msg).id.idiag_dst.to_vec();
    Some(SockInfo {
        uid,
        inode,
        srcport,
        dstport,
        src,
        dst,
    })
}

#[derive(Debug)]
pub struct SockInfo {
    pub uid: u32,
    pub inode: u32,
    pub srcport: u16,
    pub dstport: u16,
    pub src: Vec<u32>,
    pub dst: Vec<u32>,
}

fn send_diagmsg(fd: i32, family: u8, proto: u8) -> Result<()> {
    let mut msg = unsafe { std::mem::zeroed::<libc::msghdr>() };
    let mut nlh = unsafe { std::mem::zeroed::<libc::nlmsghdr>() };
    let mut sa = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    let mut req: binding::inet_diag_req_v2 = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    req.sdiag_family = family;
    req.sdiag_protocol = proto;
    req.idiag_states = TCP_ALL;
    nlh.nlmsg_len = nlmsg_length(std::mem::size_of::<binding::inet_diag_req_v2>()).try_into()?;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    nlh.nlmsg_type = binding::SOCK_DIAG_BY_FAMILY as u16;
    let mut iov_vec = Vec::<libc::iovec>::new();
    iov_vec.push(libc::iovec {
        iov_len: std::mem::size_of::<libc::nlmsghdr>(),
        iov_base: &nlh as *const libc::nlmsghdr as _,
    });
    iov_vec.push(libc::iovec {
        iov_len: std::mem::size_of::<binding::inet_diag_req_v2>(),
        iov_base: &req as *const binding::inet_diag_req_v2 as _,
    });
    msg.msg_name = &sa as *const libc::sockaddr_nl as _;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>().try_into()?;
    msg.msg_iovlen = iov_vec.len();
    msg.msg_iov = iov_vec.as_ptr() as _;
    let retval = unsafe { libc::sendmsg(fd, &msg as *const libc::msghdr as _, 0) };
    if retval > 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
