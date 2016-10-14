%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%DDoS Demo with all Attacks -
%
%
%Author : 
%Date Created : 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear all
close all
clc


disp('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%');
disp('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  DDoS Demo  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%');
disp('                                     1.UDP Attack');
disp('                                     2.ICMP Attack');
disp('                                     3.TCP Sync Attack');
disp('                                     4.TCP PSH ACK Attack');
disp('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%');
atktype=input('Choose the type of Attack demo from the list:');
switch(atktype)
    case 1 
        disp('UDP Attack Demo chosen');
        disp('************************Algols******************************');
        disp('                        1. PCA only');
        disp('                        2. LDA only');
        disp('                        3. Proposed (PCA+LDA+ALO)');
        disp('************************Algols******************************');
        algol=input('Choose the algol of Attack demo from the list: ');
        switch(algol)
            case 1
                disp('PCA Algorithm chosen');
                udp_pca_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);
            case 2
                disp('LDA Algorithm chosen');
                udp_lda();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);
            case 3
                disp('Proposed Algorithm chosen');
                udp_pclda_alo();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);
        end
    case 2 
        disp('ICMP Attack Demo chosen');
        disp('************************Algols******************************');
        disp('                        1. PCA only');
        disp('                        2. LDA only');
        disp('                        3. Proposed (PCA+LDA+ALO)');
        disp('************************Algols******************************');
        algol=input('Choose the algol of Attack demo from the list: ');
        switch(algol)
            case 1
                disp('PCA Algorithm chosen');
                icmp_pca_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
            case 2
                disp('LDA Algorithm chosen');
                icmp_lda_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
            case 3
                disp('Proposed Algorithm chosen');
                icmp_pclda_alo();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
        end
    case 3 
        disp('TCP Sync Attack Demo chosen');
        disp('************************Algols******************************');
        disp('                        1. PCA only');
        disp('                        2. LDA only');
        disp('                        3. Proposed (PCA+LDA+ALO)');
        disp('************************Algols******************************');
        algol=input('Choose the algol of Attack demo from the list: ');
        switch(algol)
            case 1
                disp('PCA Algorithm chosen');
                tcpsync_pca_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
            case 2
                disp('LDA Algorithm chosen');
                tcpsync_lda_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
            case 3
                disp('Proposed Algorithm chosen');
                tcpsync_pclda_alo();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);               
        end
    case 4 
        disp('TCP PSH ACK Attack Demo chosen');
        disp('************************Algols******************************');
        disp('                        1. PCA only');
        disp('                        2. LDA only');
        disp('                        3. Proposed (PCA+LDA+ALO)');
        disp('************************Algols******************************');
        algol=input('Choose the algol of Attack demo from the list: ');
        switch(algol)
            case 1
                disp('PCA Algorithm chosen');
                tcppshack_pca_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
            case 2
                disp('LDA Algorithm chosen');
                tcppshack_lda_only();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
            case 3
                disp('Proposed Algorithm chosen');
                tcppshack_pclda_alo();
                disp('-------------IDS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c);
                fprintf('Precision: %f\n',Precision);fprintf('Accuracy:  %f\n',Accuracy);
                fprintf('Sensitivity : %f\n',Sensitivity);fprintf('Specificity :  %f\n',Specificity);    
                fprintf('Fscore  : %f\n',Fscore);fprintf('FallOut  : %f\n',FallOut);fprintf('NPV  : %f\n',NPV);
                disp('-------------IPS Metrics-------------');
                fprintf('Percentage Correct Classification : %f%%\n',100*(1-c1));
                fprintf('Percentage InCorrect Classification : %f%%\n',100*c1);
                fprintf('Precision: %f\n',Precision1);fprintf('Accuracy:  %f\n',Accuracy1);
                fprintf('Sensitivity : %f\n',Sensitivity1);fprintf('Specificity :  %f\n',Specificity1);    
                fprintf('Fscore  : %f\n',Fscore1);fprintf('FallOut  : %f\n',FallOut1);fprintf('NPV  : %f\n',NPV1);                
        end    
end
disp('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%');

   

