%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%TCP Sync flood - PCA+LDA+ALO only 
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all;%#ok
close all;
clc


%Load the Database with both normal and udp attack records from Cloud
load('tcpsync_Feat.mat');

[pc,score,ev] = pca(X);

%%
%Plotting Inputs vs reduced PCA output
D = size(X,2);
for d=1:D
    % Original Data
    subplot(D,2,2*d-1);
    plot(X(:,d));
    ylabel(['x_' num2str(d)]);
    if d==D
        xlabel('Sample Index');
    end
    if d==1
        title('Original Data');
    end 
end

grid on;
D1 = size(score,2);
for d1=1:D1
   % Transformed Data
    subplot(D1,2,2*d1);
    plot(score(:,d1));
    ylabel(['y_' num2str(d1)]);
    if d1==D1
        xlabel('Sample Index');
    end
    if d1==1
        title('PCA Output');
    end
    grid on;  
end

%%
%LDA 
S1={};
T=zeros(numel(myStr),2);
for ji=1:numel(myStr)
    if(strcmp(myStr(ji).Class,'Attack'))
        S1{ji}=myStr(ji).Class;
        T(ji,1)=1;
    else if(strcmp(myStr(ji).Class,'Normal'))
            S1{ji}=myStr(ji).Class;
            T(ji,2)=1;
        end
    end
end

X1=score;
L = vec2ind(T')';

% [Y, W, lambda, sortorder] = LDA(X1, L);
[W, lambda, sortorder] = LDA(X1, L);

Y=X1*W;

Y1=zeros(size(Y));
%Sort it in the same feature order
for ii=1:size(Y,2)
    Y1(:,sortorder(ii))=Y(:,ii);
end

%Reduce Dimensions - by removing reduundant information
j=1;
for ii=1:size(Y1,2)
    if(sum(Y1(:,ii))==0)
%         disp('All zeros');
    else
        LDA_out(:,j)=Y1(:,ii);%#ok
        j=j+1;
    end  
end


%%
figure;

D2 = size(LDA_out,2);
for d2=1:D2
    % Original Data
    subplot(D2,2,2*d2-1);
    plot(X1(:,d2));
    ylabel(['x_' num2str(d2)]);
    if d2==D2
        xlabel('Sample Index');
    end
    if d2==1
        title('PCA Data');
    end
    grid on;
    
     % Transformed Data
    subplot(D2,2,2*d2);
    plot(Y1(:,d2));
    ylabel(['y_' num2str(d2)]);
    if d2==D2
        xlabel('Sample Index');
    end
    if d2==1
        title('LDA Output');
    end
    grid on;
    
end

%%
%ALO Optimizer
inalo=LDA_out;
[mal nal]=size(inalo);
[cg_curve,sortantlion,antlions_fitness,idx]=ALO(inalo,50,min(inalo),max(inalo),nal,@F1);

N=size(inalo,1);

%Attack Matrix
attkmatrx =zeros(2,N);

Avg_antLfit=sum(antlions_fitness)/N;
Avgby10=28;
for ii=1:N
    if(strcmp(S1{ii},'Normal'))
        attkmatrx(1,ii)=1;
    else
        attkmatrx(2,ii)=1;
    end
end


%%
% Classification using FeedForward Networks
input=antlions_fitness;
t=attkmatrx;

% Create a Pattern Recognition Network
trainFcn = 'trainscg';
hiddenLayerSize = 10;
net = patternnet(hiddenLayerSize);

% Set up Division of Data for Training, Validation, Testing
net.divideParam.trainRatio = 70/100;
net.divideParam.valRatio = 15/100;
net.divideParam.testRatio = 15/100;

% Train the Network
[net,tr] = train(net,input,t);

% Test the Network
testX = input;
testT = t;

testY = net(testX);

%Plotting
figure
plotconfusion(testT,testY);
figure
plotroc(testT,testY);

%Plot Errors
errors=testT-testY;
E=abs(errors(1,:));
figure;
plot([1:length(E)],E);%#ok
xlabel('Instances');
ylabel('Errors=target-outputs');
title('Errors Plot');

%%
%Metrics Calculation
% Actual | Neg | True Neg  | False Pos |
%        | Pos | False Neg | True Pos  |

[c,cm,ind,per] = confusion(testT,testY);

TP = cm(2,2);
TN = cm(1,1);
FP = cm(1,2);
FN = cm(2,1);

Precision = (TP / (TP + FP))*100;
Accuracy = ((TP+TN)/(TP+TN+FP+FN))*100;
Sensitivity = (TP/(TP+FN))*100;
Specificity = (TN/(FP+TN))*100;
Fscore = ((2*TP)/(2*TP+FP+FN))*100;
FallOut = ( FP /(FP + TN))*100;               %False POsitive Rate
NPV = (TN / (TN + FN))*100;                   %NEgaitve Predictive Value

ID_Met = [Precision;Accuracy;Sensitivity;Specificity;Fscore;FallOut;NPV];

%%
%Plot the attack and normal traffic with reduced dataset
figure;
plot([1:N],antlions_fitness);%#ok
xlabel('Sample Index');
ylabel('Traffic Fitness');
title('Traffic Data');

%%
%INtrusion Prevention System
Xips={};

%Reconstruct the IP and feature with class table for user 
for ii=1:N
    Xips{ii,1}=myStr(ii).SrcIP;%#ok
    Xips{ii,2}=myStr(ii).DstIP;%#ok
    Xips{ii,3}=antlions_fitness(ii);%#ok
    Xips{ii,4}=S1{ii};%#ok
end

%Filter the system and white list the attack IP sources
%Filter target
filt_tgt = zeros(2,N);
for ii=1:N
    if(strcmp(Xips{ii,4},'Normal'))
        filt_tgt(1,ii)=1;
    else
        filt_tgt(2,ii)=1; 
    end
end

input1=antlions_fitness;
tgt=filt_tgt;

% Create a Pattern Recognition Network
hiddenLayerSize = 10;
net1 = patternnet(hiddenLayerSize);

% Set up Division of Data for Training, Validation, Testing
net1.divideParam.trainRatio = 70/100;
net1.divideParam.valRatio = 15/100;
net1.divideParam.testRatio = 15/100;

% Train the Network
[net1,tr1] = train(net1,input1,tgt);

% Test the Network
outputs_ips = net1(input);

%Plotting - IPS
figure
plotconfusion(tgt,outputs_ips);
figure
plotroc(tgt,outputs_ips);

%Metrics for IPS

[c1,cm1,ind1,per1] = confusion(tgt,outputs_ips);

TP1 = cm1(2,2);
TN1 = cm1(1,1);
FP1 = cm1(1,2);
FN1 = cm1(2,1);

Precision1 = (TP1 / (TP1 + FP1))*100;
Accuracy1 = ((TP1+TN1)/(TP1+TN1+FP1+FN1))*100;
Sensitivity1 = (TP1/(TP1+FN1))*100;
Specificity1 = (TN1/(FP1+TN1))*100;
Fscore1 = ((2*TP1)/(2*TP1+FP1+FN1))*100;
FallOut1 = ( FP1 /(FP1 + TN1))*100;               %False POsitive Rate
NPV1 = (TN1 / (TN1 + FN1))*100; 

IP_Met = [Precision1;Accuracy1;Sensitivity1;Specificity1;Fscore1;FallOut1;NPV1];

%%
%Save the Black Listed SourceIP Addresses to the cloud
blist={};j=1;
for ii=1:N
    if(strcmp(Xips{ii,4},'Attack'))
        blist{j}=Xips{ii,1};%#ok
        j=j+1;
    end
end
 
[nrows, ncols]=size(blist);
%Write the blacklist to a txt file
fid1=fopen('C:\apachetomcat9\webapps\TestDoc\BlackList.xls','w');
for col=1:ncols
    fprintf(fid1,'%s\n',blist{1,col});
end
fclose(fid1);

%Save to Cloud
blacklisttoCloud()