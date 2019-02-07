use std::fmt;

#[derive(Debug)]
pub struct CardResponse {
    pub status: [u8; 2],
    pub data: Vec<u8>,
}

/// Encapulates PCSC errors and card response errors into a single error type
pub enum Error {
	PCSC(pcsc::Error),
	Response([u8; 2]),
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::PCSC(pcsc_error) => write!(f, "{:?}", pcsc_error),
            Error::Response(bytes) => write!(f, "{:x?}", bytes),
        }
    }
}
impl From<pcsc::Error> for Error {
    fn from(err: pcsc::Error) -> Error {
        Error::PCSC(err)
    }
}
impl From<[u8; 2]> for Error {
	fn from(err: [u8; 2]) -> Error {
		Error::Response(err)
	}
}

#[derive(Debug)]
pub enum Sex { Male, Female, Unknown }
pub struct CardholderInfo {
    name: String,
    sex: Sex,
}
impl fmt::Display for CardholderInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({:?})", self.name, self.sex)
    }
}

pub struct PGPCard<'a> {
    card: &'a pcsc::Card,
    keys_retrieved: bool,

    pub sig_key: [u8; 20],
    pub dec_key: [u8; 20],
    pub auth_key: [u8; 20],
}
impl fmt::Debug for PGPCard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PGP Card")
            .field("sig_key", &self.sig_key)
            .field("dec_key", &self.dec_key)
            .field("auth_key", &self.auth_key)
            .finish()
    }
}

impl PGPCard<'_> {
    pub fn new(card: &pcsc::Card) -> PGPCard {
        PGPCard {
            card,
            keys_retrieved: false,

            sig_key: [0; 20],
            dec_key: [0; 20],
            auth_key: [0; 20],
        }
    }

    pub fn select_pgp(&self) -> Result<(), Error> {
        // Send an APDU command.
        // CLA, INS_SELECT_FILE, P1_SELECT_FILE, P2_EMPTY, AID_SELECT_FILE_OPENPGP
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00];
        self.send_data(&apdu)?;
        Ok(())
    }
    pub fn get_cardholder_info(&self) -> Result<CardholderInfo, Error> {
        let apdu = [0x00, 0xCA, 0x00, 0x65, 0x00];
        let response = self.send_data(&apdu)?.data;

        let mut name = "Unknown".as_bytes();
        let mut sex = Sex::Unknown;
        for i in 2..response.len() {
            if response[i] == 0x5B {
                let length = response[i + 1] as usize;
                name = &response[i + 2..i + 2 + length];
            }
            if response[i] == 0x5F && response[i + 1] == 0x35 {
                sex = match response[i + 3] {
                    0x31 => Sex::Male,
                    0x32 => Sex::Female,
                    _ => Sex::Unknown,
                }
            }
        }
        let name = std::str::from_utf8(name).expect("Invalid UTF-8 in name").to_owned();
        let mut name: Vec<&str> = name.split("<<").collect();
        name.reverse();
        Ok(CardholderInfo {
            name: name.join(" "),
            sex,
        })
    }
    pub fn get_keys(&mut self) -> Result<(), Error> {
        if !self.keys_retrieved {
            let apdu = [0x00, 0xCA, 0x00, 0x6E, 0x00];
            let response = self.send_data(&apdu)?.data;
            for i in 2..response.len() {
                if response[i] == 0xC5 && response[i + 1] == 0x3C {
                    self.sig_key.copy_from_slice(&response[i + 2..i + 22]);
                    self.dec_key.copy_from_slice(&response[i + 22..i + 42]);
                    self.auth_key.copy_from_slice(&response[i + 42..i + 62]);
                }
            }
            self.keys_retrieved = true;
        }
        Ok(())
    }
    pub fn authenticate(&self, pin: &str) -> Result<bool, Error> {
        let mut apdu = vec![0x00, 0x20, 0x00, 0x82, pin.len() as u8];
        apdu.extend_from_slice(pin.as_bytes());
        match self.send_data(&apdu) {
            Ok(_) => Ok(true),
            Err(error) => {
                if let Error::Response(status) = error {
                    if status[0] == 0x67 {
                        eprintln!("PIN length too short");
                    }
                    else if status[0] == 0x63 {
                        let tries_left = match status[1] {
                            0xC3 => "3",
                            0xC2 => "2",
                            0xC1 => "1",
                            0xC0 => "0",
                            _ => "Unknown",
                        };
                        eprintln!("PIN incorrect. {} attempt(s) remaining.", tries_left);
                    }
                    Ok(false)
                }
                else {
                    Err(error)
                }
            }
        }
    }
    pub fn get_random_bytes(&self, count: u8) -> Result<Vec<u8>, Error> {
        let apdu = [0x00, 0x84, 0x00, 0x00, count];
        let response = self.send_data(&apdu)?.data;
        Ok(response)
    }

    pub(crate) fn send_data(&self, apdu: &[u8]) -> Result<CardResponse, Error> {
        let mut rapdu_buf = [0u8; pcsc::MAX_BUFFER_SIZE];
        let mut rapdu = self.card.transmit(apdu, &mut rapdu_buf)?.to_vec();

        let status = [rapdu[rapdu.len() - 2], rapdu[rapdu.len() - 1]];
        rapdu.truncate(rapdu.len() - 2);
        if status[0] == 0x90 && status[1] == 0x00 {
            Ok(CardResponse {
                status,
                data: rapdu,
            })
        }
        else {
            Err(Error::from(status))
        }
    }
}
