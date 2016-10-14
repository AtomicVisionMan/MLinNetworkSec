%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%TCP Sync flood - Feature Table Creation
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all;%#ok
clc


%Load the Database with both normal and udp attack records from Cloud
load('C:\apachetomcat9\webapps\TestDoc\caida1tcpsync.mat')
file2tcp=caida1tcpsync;
No_Pckts = size(file2tcp,1);

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%Extract the IP nos, Port Nos and Packet size
for ii=1:No_Pckts
    targetIP{ii}=file2tcp{ii,3};%#ok
    SrcIP{ii}=file2tcp{ii,2};%#ok
%     DstPorts{ii}=file2tcp{ii,5};%#ok
%     SrcPorts{ii}=file2tcp{ii,4};%#ok
    PacketNo{ii}=file2tcp{ii,7};%#ok
    Prototype{ii}=file2tcp{ii,6};%#ok
    Flags{ii}=file2tcp{ii,8};%#ok
end

%Find uniqueness of IP addresses, Ports and packets
uniq_targetIP = unique(targetIP,'stable');
% uniq_DstPorts = unique(DstPorts,'stable');
% uniq_SrcPorts = unique(SrcPorts,'stable');
uniq_SrcIP = unique(SrcIP,'stable');

%%
myStr=[];
%Feature Extraction
%Find the correct number of Destination IPs
for j=1:numel(uniq_SrcIP)
    Npck=0;NoBytes=0;IPtime=0;
    nudp=0;ntcp=0;nicmp=0;srcnt=0;dstcnt=0;
    s_cnt=0;f_cnt=0;a_cnt=0;p_cnt=0;
    
    for ii=1:No_Pckts
        if(strcmp(SrcIP{ii},uniq_SrcIP(j)))
            tst = Flags{ii};
            S.SrcIP=SrcIP{ii};
            S.DstIP=targetIP{ii};
           
            Npck=Npck+1;
            NoBytes = NoBytes + file2tcp{ii,7};
            IPtime=[IPtime file2tcp{ii,1}];%#ok
            
            %Prototypes
            switch(Prototype{ii})
                case {'U'}
                    proto='udp';
                    nudp=nudp+1;
                case {'S'}
                    proto='tcp';
                    s_cnt=s_cnt+1;
                    ntcp=ntcp+1;
                case {'A'}
                    proto='tcp';
                    a_cnt=a_cnt+1;
                    ntcp=ntcp+1;                
                case {'P'}
                    proto='tcp';
                    p_cnt=p_cnt+1;
                    ntcp=ntcp+1;                   
                case {'F'}
                    proto='tcp';
                    f_cnt=f_cnt+1;
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
    S.Scnt = s_cnt;
    S.Pcnt = p_cnt;
    S.Fcnt = f_cnt;
    S.Acnt = a_cnt;
    
    %Finding class
    if(and((S.Pckrate>5),(S.Nopckts>70)))
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
    X(ji,9)=myStr(ji).Scnt;%#ok
    X(ji,10)=myStr(ji).Pcnt;%#ok
    X(ji,11)=myStr(ji).Fcnt;%#ok
    X(ji,12)=myStr(ji).Acnt;%#ok
end

%sort the Nopcks in descending order
[Xnp,id]=sort(X(:,1),'descend');

for ji=1:numel(uniq_SrcIP)
    %IP addresses
    XIP{ji,1}=myStr(id(ji)).SrcIP;%#ok
    XIP{ji,2}=myStr(ji).DstIP;%#ok
end

%Save Feature Array
save tcpsync_Feat.mat X myStr XIP No_Pckts;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%End of Feature Extraction and creation of feature table 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%