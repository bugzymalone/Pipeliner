#!/bin/bash

#Pipeliner - By Bugsymalone (with paste marks from Lazyrecon and Bounty Strike)
#Lazyrecon.sh - https://github.com/nahamsec/lazyrecon
#Bountystrike - https://github.com/BountyStrike/Bountystrike-sh

#In order to run this script successfully you'll need to download/install a lot of tools and applications. Review the source for further info.

VERSION="1.0"

#Running vars, tweak as required
start=$(date +%s.%N)
dnswordlist=/root/tools/SecLists/Discovery/DNS/clean-jhaddix-dns.txt
dirdict=/root/tools/SecLists/dirbrute/dicc.txt
dirslevel=2
auquatoneThreads=5
auquatonePortLevel="xlarge"
sonarfile="/mnt/win/fdns_any.json.gz"
dirsearchThreads=50
paralvl=4
akamaidone="0"
TLD=""
curdate=$(date +'%Y-%m-%d_%H-%M-%S')
tools="$HOME/tools"
domainsfile="domains-$curdate.txt"
finaldomains="final-domains.txt"
projdir=""
verbosity="0"

splash() {

    echo " ______ _            _ _                  ";
    echo " | ___ (_)          | (_)                 ";
    echo " | |_/ /_ _ __   ___| |_ _ __   ___ _ __  ";
    echo " |  __/| | '_ \ / _ \ | | '_ \ / _ \ '__| ";
    echo " | |   | | |_) |  __/ | | | | |  __/ |    ";
    echo " \_|   |_| .__/ \___|_|_|_| |_|\___|_|    ";
    echo "         | |                              ";
    echo "         |_|                              ";


	echo -e """
 An amalgamation of common enumeration and analysis tools to make your life easier ...

	    pipeliner.sh <action> [TLD domain]
	    pipeliner.sh runall
	    pipeliner.sh apd [DNS active/passive discovery]
	    pipeliner.sh pd  [DNS passive discovery]
	    pipeliner.sh ad  [DNS active discover]
	    pipeliner.sh we  [Web enumeration]
	    pipeliner.sh ns  [Network scanning]
	    pipeliner.sh ms  [Misc scanning]
	    pipeliner.sh sm  [Smuggler scanning]

	"""
	exit 1
}

passivednsenum() {
    echo "Subdomain Discovery with sonar, subind3r, amass, subfinder and gobuster"
    # Passively find subdomains
	echo "[*] Starting Sonar search ..."

	if [ $verbosity == "1" ]
	then

	    if [ ! -f $sonarfile ]
	    then
			echo -ne '\007'
			tee "Sonar file not found, check configuration" >> $projdir/sonar-$domainsfile 
	    else
			pv $sonarfile \
			 | pigz -dc \
			 | grep -P "\.($TLD)\"," \
			 | jq -r '.name' \
			 | tee $projdir/sonar-$domainsfile 
	    fi
	fi

    echo "Starting sublister search..."
    python3 ~/tools/Sublist3r/sublist3r.py -d $TLD -t 10 -v -o $projdir/sublister-$domainsfile 

    # Kill amass after 300 seconds incase it hangs for some reason
    timeout 300s amass enum -passive -o $projdir/amass-$domainsfile -log $projdir/amass.log -d $TLD 
    subfinder -d $TLD > $projdir/subfinder-$domainsfile 

    #Chaos AD Enum
    /root/go/bin/chaos -d $TLD -key <insert your key> -o $projdir/chaos-$domainsfile

    #Aggergate everything and remove duplicates
    cat $projdir/sonar-$domainsfile $projdir/sublister-$domainsfile $projdir/amass-$domainsfile $projdir/subfinder-$domainsfile $projdir/chaos-$domainsfile | sort -u > $projdir/combined-$domainsfile

    #Remove non-exsitant domains and ensure only target domains are in our list
    parallel -j 32 nslookup < $projdir/combined-$domainsfile | grep "^Name" | awk '{print $2}' | grep $TLD > $projdir/$domainsfile

    #set final domains file
    sort -u $projdir/$domainsfile >> $projdir/$finaldomains
}

activednsenum() {
    echo "[*] Starting Active DNS hunting"

       if [ $verbosity == "1" ]
       then
            gobuster dns -d $TLD -w $dnswordlist --output $projdir/gobuster-$domainsfile
	    echo "[*] Waiting for amass and subfinder to finish..."
	    wait
	    cat $projdir/gobuster-$domainsfile | sort -u >> $projdir/$domainsfile
      fi

    #set final domains file
    sort -u $projdir/$domainsfile >> $projdir/$finaldomains

}

webenum(){
	
    #Run wayback and then httprobe (which may include additional domains from wayback)
	
    #echo "[*] Checknig Wayback for urls"
    # Find domains urls from wayback
    #cat $projdir/$finaldomains | waybackurls > $projdir/wayback/waybackurls.txt

    # Maybe wayback has some uniq domains
    #cat $projdir/$finaldomains | unfurl domains | sort | uniq > $projdir/wayback-domains.txt
    #sort -u $projdir/$finaldomains -o $projdir/$finaldomains
    
    #echo "[*] Extracting potentially interesting wayback extensions to wayback dir"
	#cat $projdir/wayback/waybackurls.txt | sort -u | unfurl --unique keys > $projdir/wayback/paramlist.txt
	#cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.js(\?|$)" | sort -u > $projdir/wayback/jsurls.txt
	#cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.php(\?|$)" | sort -u > $projdir/wayback/phpurls.txt
	#cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.aspx(\?|$)" | sort -u > $projdir/wayback/aspxurls.txt
	#cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.jsp(\?|$)" | sort -u > $projdir/wayback/jspurls.txt
	
    # Find HTTP servers from domains
    echo "[*] Running Httprobe against collected sub-domains"
    cat $projdir/$finaldomains | httprobe > $projdir/httpalive.txt

}

runwayback(){

    #This function contains duplicate code, incase we just want to run wayback specifically
	
    echo "[*] Checknig Wayback for urls"
    # Find domains urls from wayback
    cat $projdir/final-domains.txt | waybackurls > $projdir/wayback/waybackurls.txt

    # Maybe wayback has some uniq domains
    cat $projdir/wayback/waybackurls.txt | unfurl domains | sort | uniq > $projdir/wayback-domains.txt
    sort -u $projdir/$finaldomains -o $projdir/$finaldomains
    
    echo "[*] Extracting potentially interesting wayback extensions to wayback dir"
	cat $projdir/wayback/waybackurls.txt | sort -u | unfurl --unique keys > $projdir/wayback/paramlist.txt
	cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.js(\?|$)" | sort -u > $projdir/wayback/jsurls.txt
	cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.php(\?|$)" | sort -u > $projdir/wayback/phpurls.txt
	cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.aspx(\?|$)" | sort -u > $projdir/wayback/aspxurls.txt
	cat $projdir/wayback/waybackurls.txt | sort -u | grep -P "\w+\.jsp(\?|$)" | sort -u > $projdir/wayback/jspurls.txt

}

akamaitest(){

    echo "[*] Scanning for Akamai fronted sites"
       for akhost in $(cat $projdir/httpalive.txt)
        do
           if host $akhost | grep -q 'akamaiedge'; then
                echo "Akamai fronted host identified: $akhost"
                echo $akhost >> $projdir/akamai-hosts.txt           
           fi
        done	
	
	echo "[*] Remove Akamai fronted sites from main httpalive.txt"
	
	#remove akamai domains from our httpalive file and set variable to indicate this.
	akamaidone="1"
	
	#Take Akamai hosts out of main httpalive file (only if not empty)
	if [ ! -f $projdir/akamai-hosts.txt ]; then
		grep -Fvx -f $projdir/akamai-hosts.txt $projdir/httpalive.txt | sort -u -o $projdir/httpalive.txt
	fi
}


jsscanning(){

    #If we haven't filtered Akamai hosts, do it now
    if [ "$akamaidone" != "1" ]; then
    	akamaitest
    fi
	
    echo "[*] Running GetJS to obtain valid Javascript locations ..."
    cat $projdir/httpalive.txt | /root/go/bin/getJS -complete -verbose > $projdir/alive-js-files.txt
    cat $projdir/alive-js-files.txt | grep http | grep -v "Getting sources" | sort -u -o $projdir/alive-js-files-clean.txt

    echo "[*] Getting links within JS files with Linkfinder"
    
       for lfind in $(cat $projdir/alive-js-files-clean.txt)
        do
	 echo "Searching: $lfind" >> $projdir/js-links.txt
	 python3 /root/tools/LinkFinder/linkfinder.py -i $lfind -o cli >> $projdir/js-links.txt
        done	


    echo "[*] Compiling custom wordlists based on JS words"
    #avoid 3rd party Javascript libs from the usual suspects
    cat $projdir/alive-js-files.txt | grep -v "youtube" | grep -v "google" | grep -v "cloudflare" | python3 /root/tools/getjswords/getjswords.py >> $projdir/jswords.txt
	
    #Filter crap from the custom dictionary file
    cat $projdir/jswords.txt | awk 'length($0)>3' | awk 'length($0)<26' | sed '/^[[:alpha:]]*$/!d' | sort -u -o $projdir/jswords-clean.txt

    #Transform httpalive.txt file, strip http/s and sort into uniq domain names and send into dirsearch with our custom jswords
    cat $projdir/httpalive.txt | cut -d'/' -f3 | cut -d':' -f1 | sort -u -o $projdir/jsdirhosts.txt 

    echo "[*] Running dirsearch with custom JS words dictionary. Parallel Count: $paralvl"
    cat $projdir/jsdirhosts.txt | parallel -j $paralvl python3 /root/tools/dirsearch/dirsearch.py -t 30 --max-retries=2 --timeout=5 --random-agents -x 403,301,302,500,501,502 -E --plain-text-report=$projdir/jsdirsearch/dirs.{} -w $projdir/jswords-clean.txt -u {}

}

dirscanning(){

	#If we haven't filtered Akamai hosts, do it now
	if [ "$akamaidone" != "1" ]; then
		akamaitest
	fi
	
	#Transform httpalive.txt file, strip http/s and sort into uniq domain names and send into dirsearch with our custom jswords
	cat $projdir/httpalive.txt | cut -d'/' -f3 | cut -d':' -f1 | sort -u -o $projdir/dirhosts.txt 

	cat $projdir/dirhosts.txt | parallel -j $paralvl python3 /root/tools/dirsearch/dirsearch.py -t 30 --max-retries=2 --timeout=5 --random-agents -x 403,301,302,500,501,502 -E --plain-text-report=$projdir/dirsearch/dirs.{} -W $dirdict -u {}
}

runhakrawler(){

   echo "[*] Combing sites with Hakrawler"
       for hakhost in $(cat $projdir/httpalive.txt)
        do
           echo "[*] Running hakrawler against $hakhost"
           /root/go/bin/hakrawler -url $hakhost -js -urls -linkfinder -depth 3 -forms -robots -outdir $projdir/hakrawler > $projdir/hakrawler/hakhost.$hakhost
        done

}

networkscanning(){

    # Find IP-addresses
    echo "[*] Running Massdns to identify target IP addresses"
    cat $projdir/$finaldomains | massdns --output S -q -r /root/tools/resolvers.txt > $projdir/massdns-$curdate.txt
    cat $projdir/massdns-$curdate.txt | grep -w -E A | cut -d " " -f3 | sort -u | head -n -1 > $projdir/ips-$curdate.txt

    if [ -s $projdir/ips-$curdate.txt ]
    then
        echo "[*] Running Masscan across target IPs"
        # Find open-ports on ip list
        sudo masscan -iL $projdir/ips-$curdate.txt --rate 5000 -p1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,300-301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,591,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,832,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2082,2087,2095-2096,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2480,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242-4243,4279,4321,4343,4443-4446,4449,4550,4567,4662,4711-4712,4848,4899-4900,4993,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5104,5108,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6379,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7396,7402,7435,7443,7474,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8014,8021-8022,8031,8042,8045,8069,8080-8091,8093,8099-8100,8118,8123,8172,8180-8181,8192-8194,8200,8222,8243,8254,8280-8281,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8834,8873,8880,8888,8899,8983,8994,9000-9003,9009-9011,9040,9043,9050,9060,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9443,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9800,9876-9878,9898,9900,9917,9929,9943-9944,9968,9981,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,12443,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18091-18092,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20720,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27018,27352-27353,27355-27356,27715,28017,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389 -oX $projdir/masscan-$curdate.xml

        open_ports=$(cat $projdir/masscan-$curdate.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
        sudo nmap -sVC -p$open_ports --open -v -T4 -Pn -iL $projdir/$finaldomains -oG $projdir/nmap-$curdate.txt
    else
        echo "[*] Skipping Masscan, ips-$curdate.txt was empty or does not exist"
    fi

}

runaquatone(){

    echo "Running Aquatone (with your variable parameters)"
    cat $projdir/httpalive.txt | aquatone -threads $auquatoneThreads -out $projdir/aquatone -silent -ports $auquatonePortLevel
}

miscscanning(){
    echo "Subdomain takeover checks"
    /root/go/bin/subzy -TLDs $projdir/$finaldomains | grep -i -v -E "not vulnerable|ERROR" | tee -a $projdir/subtakeovers-$curdate.txt

	#If we haven't filtered Akamai hosts, do it now
	if [ "$akamaidone" != "1" ]; then
		akamaitest
	fi

    #Smuggler Scan
    smugglerscan

}

smugglerscan(){


    #If we haven't filtered Akamai hosts, do it now
    if [ "$akamaidone" != "1" ]; then
    	akamaitest
    fi

    #Run smuggling scanner
    echo "[*] Running smuggler scans"
    for smughost in $(cat $projdir/httpalive.txt)
    do       
       /root/tools/smuggler/smuggler.py --url $smughost -x -l $projdir/smuggle.$smughost.txt
    done
}


# main()

if [[ $2 == "." ]]; then
	projdir=$PWD
	echo "[*] Running from current working directory" 
else
	projdir="$2/$curdate"
fi


if [[ ! $1 == "" ]]; then
                        TLD=$2
                        mkdir -p $projdir
                        mkdir $projdir/jswords
                        mkdir $projdir/jsdirsearch
                        mkdir $projdir/dirsearch
                        mkdir $projdir/hakrawler
                        mkdir $projdir/wayback

                        if [[ $2 == "" ]]; then
                                echo "[-] Please specify a domain to scan ..."
                                splash
				exit
                        fi
fi


if [[ $1 == "" ]] || [[ $1 == "-h" ]] || [[ $1 == "--help" ]]; then
	splash

elif [[ $1 == "runall" ]]; then

	if [[ ! $2 == "" ]]; then
			
			TLD=$2
			
			mkdir -p $projdir
			mkdir $projdir/jswords
			mkdir $projdir/jsdirsearch
			mkdir $projdir/dirsearch
			mkdir $projdir/hakrawler
			mkdir $projdir/wayback

			if [[ $2 == "" ]]; then
				echo "[-] Please specify a domain to scan ..."
				splash
			fi
		
	#Run from the top
	passivednsenum
	activednsenum
	webenum
	jsscanning
	dirscanning
	runhakrawler
        runaquatone
        miscscanning
        networkscanning

	else
		splash
	fi
elif [[ $1 == "pd" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            passivednsenum
        else
            splash
        fi
elif [[ $1 == "ad" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            activednsenum
        else
            splash
        fi
elif [[ $1 == "we" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
				webenum
				runwayback
				jsscanning
				dirscanning
				runhakrawler
        else
            splash
        fi
elif [[ $1 == "ns" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            networkscanning
        else
            splash
        fi
elif [[ $1 == "ms" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            miscscanning
        else
            splash
        fi
elif [[ $1 == "sc" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            smugglerscan
        else
            splash
        fi
elif [[ $1 == "js" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            jsscanning
        else
            splash
        fi
elif [[ $1 == "ds" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            dirscanning
        else
            splash
        fi
elif [[ $1 == "wb" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            runwayback
        else
            splash
        fi
elif [[ $1 == "ak" ]]; then
        if [[ ! $2 == "" ]]; then
            TLD=$2
            akamaitest
        else
            splash
        fi

else

    splash
fi

duration=$(echo "$(date +%s.%N) - $start" | bc)
execution_time=`printf "%.2f seconds" $duration`

echo -e "Scanning complete. Time: $execution_time"
#\n Unique domains: x \n Valid Domains: x \n Valid Website: x \n Valid 200 HTTP requests: x \n
echo "Compiling basic report"

