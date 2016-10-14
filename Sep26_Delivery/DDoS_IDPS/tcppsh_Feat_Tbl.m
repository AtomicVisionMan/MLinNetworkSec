%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%TCP PSH ACK flood - Feature Table Creation 
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all;%#ok
clc


%Load the Database with both normal and udp attack records from Cloud
load('C:\apachetomcat9\webapps\TestDoc\tcp2tracePsh.mat')
file2tcp=filenew;
No_Pckts = size(file2tcp,1);

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%Extract the IP nos, Port Nos and Packet size
for ii=1:No_Pckts
    targetIP{ii}=file2tcp{ii,3};%#ok
    SrcIP{ii}=file2tcp{ii,2};%#ok
    DstPorts(ii)=file2tcp{ii,5};%#ok
    SrcPorts(ii)=file2tcp{ii,4};%#ok
    PacketNo{ii}=file2tcp{ii,6};%#ok
    Flags{ii}=file2tcp{ii,7};%#ok
    Prototype{ii}=file2tcp{ii,7};%#ok
end

%Find uniqueness of IP addresses, Ports and packets
uniq_targetIP = unique(targetIP,'stable');
uniq_DstPorts = unique(DstPorts,'stable');
uniq_SrcPorts = unique(SrcPorts,'stable');
uniq_SrcIP = unique(SrcIP,'stable');

%%
%Source and Destination IPs
if(strcmp(uniq_SrcIP{2},uniq_targetIP{1}))
    DST=uniq_targetIP{1};
end

SRC={};j=1;
for kk=1:numel(uniq_SrcIP)
    m = uniq_SrcIP{kk};
    if(strcmp(m,'1.1.236.8'))
    else
        SRC{j}=m;%#ok
        j=j+1;
    end
end

%%
myStr=[];
%Feature Extraction
%Find the correct number of Destination IPs
for j=1:(numel(uniq_SrcIP)-1)
    Npck=0;NoBytes=0;IPtime=0;
    nudp=0;ntcp=0;nicmp=0;srcnt=0;dstcnt=0;
    s_cnt=0;f_cnt=0;a_cnt=0;p_cnt=0;
    
    for ii=1:No_Pckts
        tst = Flags{ii};
        if(or(strcmp(tst,'A'),strcmp(tst,'P')))      
            S.SrcIP = SRC{j};
            S.DstIP = DST;    
           
            if(or(strcmp(SrcIP{ii},SRC(j)),strcmp(targetIP{ii},SRC(j))))
            %No of packets received 
                if(PacketNo{ii}>0)
                    Npck=Npck+1;
                end
                NoBytes = NoBytes + file2tcp{ii,6};
                IPtime=[IPtime file2tcp{ii,1}];%#ok
            end
        end  
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
            
            %Src Count
%             if(DstPorts{ii})
%                 srcnt = srcnt+1;
%             end
            
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
    if(and((S.AvgPckSz>20),(S.Nopckts>50)))
        S.Class ='Attack';
    else
       S.Class ='Normal';
    end
    
    myStr = [myStr S];%#ok
end

%%
%Copy calculated features into a feature array
X=[];XIP={};
for ji=1:numel(uniq_SrcIP)-1
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

for ji=1:numel(uniq_SrcIP)-1
    %IP addresses
    XIP{ji,1}=myStr(id(ji)).SrcIP;%#ok
    XIP{ji,2}=myStr(ji).DstIP;%#ok
end

%Save Feature Array
save tcpPsh_Feat.mat X myStr XIP No_Pckts;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%End of Feature Extraction and creation of feature table 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%