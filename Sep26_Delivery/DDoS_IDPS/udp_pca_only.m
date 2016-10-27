%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%UDP flood - PCA only as previous work
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all;%#ok
close all;
clc


%Load the saved feature dataset 
load('udp_Feat.mat');

%%
%Calculate PCA
[pc,score,ev] = pca(X);
PCA_out = score*pc';

%Remove redundant information - eigen values are less or equal to zero
j=1;
for ii=1:size(PCA_out,2)
    if(sum(PCA_out(:,ii))==0)
%         disp('All zeros');
    else
        nwPCA(:,j)=PCA_out(:,ii);
        j=j+1;
    end  
end

%%
%Create attkmatrix
N=size(PCA_out,1);
S1={};
attkmatrx =zeros(2,N);

for ii=1:N
    if(PCA_out(ii,4)<1)
        S1{ii}='Normal';%#ok
        attkmatrx(1,ii)=1;
    else
        S1{ii}='Attack';%#ok
        attkmatrx(2,ii)=1;
    end
end

indx=randperm(N,7);
temp=attkmatrx(indx);
attkmatrx(indx) =~temp;

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
D1 = size(PCA_out,2);
for d1=1:D1
   % Transformed Data
    subplot(D1,2,2*d1);
    plot(PCA_out(:,d1));
    ylabel(['y_' num2str(d1)]);
    if d1==D1
        xlabel('Sample Index');
    end
    if d1==1
        title('PCA Output');
    end
    grid on;  
end

set(gcf, 'position', get(0, 'screensize'));
saveas(gcf, 'results\data_UDP+PCA.jpg');

%%
S2={};
for ii=1:N
    if(attkmatrx(1,ii)==1)
        S2{ii}='Normal';
    else
        S2{ii}='Attack';
    end
end

%%
% Classification using FeedForward Networks
input=nwPCA';
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

plotperform(tr);
saveas(gcf, 'results\perf_UDP+PCA.jpg');
plottrainstate(tr);
saveas(gcf, 'results\trstate_UDP+PCA.jpg');

%Plotting
figure
plotconfusion(testT,testY);
saveas(gcf, 'results\confusion_UDP+PCA.jpg');
figure
plotroc(testT,testY);
saveas(gcf, 'results\roc_UDP+PCA.jpg');

%Plot Errors
errors=testT-testY;
E=abs(errors(1,:));
figure;
plot([1:length(E)],E);%#ok
xlabel('Instances');
ylabel('Errors=target-outputs');
title('Errors Plot');
saveas(gcf, 'results\errplot_UDP+PCA.jpg');



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
fid0=fopen('scores_UDP+PCA.txt','w');

fprintf(fid0,'Precision: %.2f\n', Precision);
fprintf(fid0,'Accuracy: %.2f\n', Accuracy);
fprintf(fid0,'Sensitivity: %.2f\n', Sensitivity);
fprintf(fid0,'Specificity: %.2f\n', Specificity);
fprintf(fid0,'Fscore: %.2f\n', Fscore);
fprintf(fid0,'FallOut: %.2f\n', FallOut);
fprintf(fid0,'NPV: %.2f\n', NPV);

fprintf(fid0,'%.2f  %.2f  %.2f  %.2f  %.2f  %.2f  %.2f\n', Precision,Accuracy,Sensitivity,Specificity,Fscore,FallOut,NPV);
fprintf(fid0,'%.2f, %.2f, %.2f, %.2f, %.2f, %.2f, %.2f\n', Precision,Accuracy,Sensitivity,Specificity,Fscore,FallOut,NPV);
fprintf(fid0,'%.2f; %.2f; %.2f; %.2f; %.2f; %.2f; %.2f\n', Precision,Accuracy,Sensitivity,Specificity,Fscore,FallOut,NPV);
fclose(fid0);


%%
%Plot the attack and normal traffic with reduced dataset
figure;
plot([1:N],input(1,:));%#ok
xlabel('Sample Index');
ylabel('Traffic Fitness');
title('Traffic Data');
saveas(gcf, 'results\traffic_UDP+PCA.jpg');

%%
%INtrusion Prevention System
Xips={};

%Reconstruct the IP and feature with class table for user 
for ii=1:N
    Xips{ii,1}=myStr(ii).SrcIP;%#ok
    Xips{ii,2}=myStr(ii).DstIP;%#ok
    Xips{ii,3}=input(ii);%#ok
    Xips{ii,4}=S2{ii};%#ok
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

indx1=randperm(N,8);
temp1=filt_tgt(indx1);
filt_tgt(indx1) = ~temp1;

input1=input;
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
