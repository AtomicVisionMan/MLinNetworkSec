%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%ICMP flood - Feature Table Creation 
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all;%#ok
clc


%Load the Database with both normal and icmp attack records from Cloud
load('C:\apachetomcat9\webapps\TestDoc\caida1icmp.mat')
file2icmp=caida1icmp;
No_Pckts = size(file2icmp,1);

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%Extract the IP nos, Port Nos and Packet size
for ii=1:No_Pckts
    targetIP{ii}=file2icmp{ii,3};%#ok
    SrcIP{ii}=file2icmp{ii,2};%#ok
    PacketNo{ii}=file2icmp{ii,5};%#ok
    Prototype{ii}=file2icmp{ii,4};%#ok
end

%Find uniqueness of IP addresses, Ports and packets
uniq_targetIP = unique(targetIP,'stable');
uniq_SrcIP = unique(SrcIP,'stable');


%%
myStr=[];
%Feature Extraction
%Find the correct number of Destination IPs
for j=1:numel(uniq_SrcIP)
    Npck=0;NoBytes=0;IPtime=0;
    nudp=0;ntcp=0;nicmp=0;srcnt=0;dstcnt=0;
    for ii=1:No_Pckts
        if(strcmp(SrcIP{ii},uniq_SrcIP(j)))
            S.SrcIP=SrcIP{ii};
            S.DstIP=targetIP{ii};
            
            Npck=Npck+1;
            NoBytes = NoBytes + file2icmp{ii,5};
            IPtime=[IPtime file2icmp{ii,1}];%#ok
            
            %Prototypes
            switch(Prototype{ii})
                case {'U'}
                    proto='udp';
                    nudp=nudp+1;
                case {'S'}
                    proto='tcp';
                    ntcp=ntcp+1;
                case {'A'}
                    proto='tcp';
                    ntcp=ntcp+1;                
                case {'P'}
                    proto='tcp';
                    ntcp=ntcp+1;                   
                case {'F'}
                    proto='tcp';
                    ntcp=ntcp+1;
                otherwise
                    proto='icmp';
                    nicmp=nicmp+1;                     
            end            
            
        end
    end
    
    %Other feature calculations
    time1 = IPtime(Npck)-IPtime(1);
    AvgPckS = NoBytes/Npck;
    
    if(Npck==1)
        PcktR = Npck;
        ByteR = NoBytes;
    else
        PcktR = Npck/time1;
        ByteR = NoBytes/time1;
    end

    %Ratio of protocol
    ratioudp=nudp/Npck;
    ratiotcp=ntcp/Npck;
    ratioicmp=nicmp/Npck;
    
    %SrcCnt and DstCnt
    srcnt = numel(uniq_SrcIP);
    dstcnt = numel(uniq_targetIP); 
    
    %Store Feature values in a structure    
    S.Nopckts = Npck;
    S.AvgPckSz = AvgPckS;
    S.Nobytes = NoBytes;
    S.Pckrate = PcktR;
    S.Bitrate = ByteR;
    S.Prototype = proto;
    S.RatioUDP = ratioudp;
    S.RatioTCP = ratiotcp;
    S.RatioICMP = ratioicmp;
    S.SrcCnt = srcnt;
    S.DstCnt = dstcnt;    
    
    %Finding class
    if(and(S.Nopckts>900,S.Bitrate>1000))
        S.Class ='Attack';
    else
       S.Class ='Normal';
    end
    
    myStr = [myStr S];%#ok
end


%%
%Copy calculated features into a feature array
X=[];XIP={};
for ji=1:numel(uniq_SrcIP)
    %Features
    X(ji,1)=myStr(ji).Nopckts;%#ok
    X(ji,2)=myStr(ji).AvgPckSz;%#ok
    X(ji,3)=myStr(ji).Nobytes;%#ok
    X(ji,4)=myStr(ji).Pckrate;%#ok
    X(ji,5)=myStr(ji).Bitrate;%#ok
    X(ji,6)=myStr(ji).RatioUDP;%#ok
    X(ji,7)=myStr(ji).RatioTCP;%#ok
    X(ji,8)=myStr(ji).RatioICMP;%#ok
    X(ji,9)=myStr(ji).SrcCnt;%#ok
    X(ji,10)=myStr(ji).DstCnt;%#ok
end

%sort the Nopcks in descending order
[Xnp,id]=sort(X(:,1),'descend');

for ji=1:numel(uniq_SrcIP)
    %IP addresses
    XIP{ji,1}=myStr(id(ji)).SrcIP;%#ok
    XIP{ji,2}=myStr(ji).DstIP;%#ok
end

%Save Feature Array
save icmp_Feat.mat X myStr XIP No_Pckts;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%End of Feature Extraction and creation of feature table 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%