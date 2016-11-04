%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%UDP flood - Feature Table Creation
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all;%#ok
close all;
clc


%Load the Database with both normal and udp attack records from Cloud
load('/Users/leon/Developer/MachineLearning/MLinNetworkSec/Sep26_Delivery/Databases/trace1udp.mat')
file2udp=file1udp;
No_Pckts = size(file2udp,1);

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%Extract the IP nos, Port Nos and Packet size
for ii=1:No_Pckts
    targetIP{ii}=file2udp{ii,3};%#ok
    SrcIP{ii}=file2udp{ii,2};%#ok
    DstPorts(ii)=file2udp{ii,5};%#ok
    SrcPorts(ii)=file2udp{ii,4};%#ok
    PacketNo{ii}=file2udp{ii,7};%#ok
    Prototype{ii}=file2udp{ii,6};%#ok
end

%Find uniqueness of IP addresses, Ports and packets
uniq_targetIP = unique(targetIP,'stable');
uniq_DstPorts = unique(DstPorts,'stable');
uniq_SrcPorts = unique(SrcPorts,'stable');
uniq_SrcIP = unique(SrcIP,'stable');

%%
myStr=[];
%Feature Extraction
%Find the correct number of Destination IPs
for j=1:numel(uniq_SrcIP)
%     printf('IP %d', str2num(j));
    disp([ 'IP ' int2str(j) ]);
    Npck=0;NoBytes=0;IPtime=0;
    nudp=0;ntcp=0;nicmp=0;srcnt=0;dstcnt=0;
    for ii=1:No_Pckts
        if(strcmp(SrcIP{ii},uniq_SrcIP(j)))
            S.SrcIP=SrcIP{ii};
            S.DstIP=uniq_targetIP;
            
            Npck=Npck+1;
            NoBytes = NoBytes + file2udp{ii,5};
            IPtime=[IPtime file2udp{ii,1}];%#ok
            
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
            
            %Src Count
%             if(DstPorts{ii})
%                 srcnt = srcnt+1;
%             end
            
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
    srcnt = numel(uniq_DstPorts);
    dstcnt = numel(uniq_SrcIP); 
   
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
    if(and((S.AvgPckSz>900),(S.Nopckts>50)))
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
save udp_Feat.mat X myStr XIP No_Pckts;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%End of Feature Extraction and creation of feature table 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%