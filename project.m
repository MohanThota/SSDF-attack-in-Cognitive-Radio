clc;
clear;
close all;
%module 1 local spectrum sensing
%module 2 sensing report sharing
%module 3 kernel density estimation 
%module 4 confidence interval based SSDF attacker prediction
%module 0 min no of samples
disp('------Module 0 ---- min no of samples-----')
pd=0.9;
pf=0.1;
pfin=qfuncinv(pf);
pdin=qfuncinv(pd);
Nmina=[];
for snr= -10:1:0
    hi=1;
    hi2=hi*hi;
    snrlog=abs(10.^(snr/10));
    snr1=snrlog*hi2;
    k=snr1*snr1;
    Nmin3=(pdin)*(snr1+1);
    Nmin4=pfin-Nmin3;
    Nmin2=Nmin4*Nmin4;
    Nmin=Nmin2/k;
    disp(Nmin);
    Nminr=round(Nmin);
    Nmina=[Nmina Nminr];
end
snr= -10:1:0;
figure(6);
semilogy(snr,Nmina,'o-');
grid('on');
xlabel("snr in dB");
ylabel("min no samples required");
title('MINIMUM NO OF SAMPLES VS SNR');
 
disp('%----------Module 2 Sensing report sharing ------------%');
    %(Report Sharing)
    conv=pi/180;
    abc_corr = 0.5*conv;
    p_corr=exp(-23.*abc_corr.*abc_corr*0.125*0.125);
    abc_ind = 180*conv;
    p_ind=exp(-23.*abc_ind.*abc_ind*0.5*0.5);
 
    
 M=80;
dBSNR = -13:1:-2;
disp('========== Performance For Different Malicious User Percentage ============');
jN=1;
    for N = 0.15:0.05:0.25
        fprintf('For Malicious users %1.2f%%\n',N*100);
         tt=1;
        
         for Beta = 0.0125:0.0125:0.1375
            L=Nmina(tt);
            pf_corr =0;
            Pabnorm =0;   
                for t=1:L
                    for i = 1:M
                      for j =1:M
                          if i <=j
                              R_corr(i,j) = p_corr^(j-i);
                          elseif i>j
                              R_corr(i,j) = conj(R_corr(j,i));
                          end
                      end
                    end
                    var_h = 1;
                    var_n = var(rand(1,M));
                    P = 10^(dBSNR(tt)/10);
                    %under condition H0 only noise present
                    mean_H0 = N*M*var_n;
                    var_H0 = N*M*var_n^2;
                    decision_statistics_H0 = sqrt(var_H0)*randn(1,1) +mean_H0;
                    %unser condition H1 signal and noise both are present
                    mean_H1=N*M*(P*var_h + var_n);
                    var_H1_corr = 0;
                    lambda_corr = eig(R_corr);
                   % ('========== Module 3 Kernal Density ==========');
                    for k= 1:M
                        var_H1_corr = var_H1_corr + (P*var_h*lambda_corr(k) + var_n)^2;
                    end
                    var_H1_corr = var_H1_corr*N;
                    decision_statistics_H1_corr = sqrt(var_H1_corr)*randn(1,1) +mean_H1;
                    confidence_interval = 0;
                    %('========== Module 4 Density based SSDF detection ==========');
                    %standard gaussian distribution
                    for l=1:M
                        confidence_interval = confidence_interval + (P*var_h*lambda_corr(l)+var_n)^2;
                    end
                    tcorr=sqrt(confidence_interval*N);
                    % Confidence interval Eq(8)
                    Confid_interval=abs(abs(qfuncinv(Beta)*tcorr)-N*M*(P*var_h+var_n));
                    
                    if (decision_statistics_H0 >= Confid_interval)
                        pf_corr=pf_corr+1;%normal user prediction
                    else
                        Pabnorm = Pabnorm+1;
                    end
                end
           
            pff_corr(tt)=pf_corr/L;
            Pdd_corr(tt)=1-(pf_corr/L);
            tt=tt+1;
        end
        Pma1User(:,jN)=Pdd_corr;
        jN=jN+1;
        
    end
   
   Beta = 0.0125:0.0125:0.1375;
    figure(2);
    plot(Beta,Pma1User,'s-');
    grid on;
   
   
    
    ylabel('success probaility');
    xlabel('Beta---confidence interval');
    legend('Malicious 15%','Malicious 20%','Malicious 25%');
    title('N=80')
   

    
    disp('========== Performance for Different Number of Secondary users ===========');
    jS=1;
    dBSNR = -10:0;

    for M = 10:20:50
        fprintf('For Secondary User %d\n',M);
        tt=1;
        for N=0.15:0.025:0.40
            pf_corr =0;
            Pabnorm =0;
            % neighbourhood SU user prediction using Correlation estimation
            L=Nmina(tt);
            for t=1:L
                for i = 1:M
                    for j=1:M
                        if i<= j
                            R_corr(i,j) = p_corr^(j-i);
                        elseif i>j
                            R_corr(i,j) = conj(R_corr(j,i));
                        end
                    end
                end
                
                var_h = 1;
                var_n = var(rand(1,M));
                P = 10^(dBSNR(tt)/10);
                mean_H0 = N*M*var_n;
                var_H0 = N*M*var_n^2;
                decision_statistics_H0 = sqrt(var_H0)*randn(1,1) + mean_H0;
                % under condition H1 signal and noise botha re present 
                mean_H1=N*M*(P*var_h+var_n);
                var_H1_corr=0;
                lambda_corr=eig(R_corr);
                alpha=0.1;
                %kernel density estimator Eq(7)
                for k=1:M
                    var_H1_corr=var_H1_corr+(P*var_h*lambda_corr(k)+var_n)^2;
                end 
                var_H1_corr= var_H1_corr*N;
                decision_statistics_H1_corr=sqrt(var_H1_corr)*randn(1,1)+mean_H1;
                Confidence_interval=0;
                % standard gaussian distribution
                for l=1:M
                    Confidence_interval = Confidence_interval + (P*var_h*lambda_corr(l) + var_n)^2;
                end
                tcorr=sqrt(Confidence_interval*N);
                % confidence interval Eq(8)
                Confid_interval=abs(abs(qfuncinv(alpha)*tcorr)-N*M*(P*var_h+var_n));
                if (decision_statistics_H0 >= Confid_interval)
                    pf_corr=pf_corr+1;
                else
                    Pabnorm=Pabnorm+1;
                end
            end
            pff_corr(tt)=pf_corr/L;
            pdd_corr(tt)=1-(pf_corr/L);
           tt=tt+1;
        end
        PSuser(:,jS)=pdd_corr;
        jS=jS+1;
        
    end
    N=0.15:0.025:0.40; 
    figure(4)
    plot(N,sort(PSuser,'descend'),'o-'); 
    grid on;
    ylabel('success probaility');
    xlabel('percentage of malicious user');
    legend('user=10','user=30','user=50');
    title('Beta =1')

  disp('============ Performance for Different Beta value ===========');
    jB=1;
    dBSNR = -10:0;

      p_corr=1;
      M=20;
    for Beta=0.025:0.025:0.1
        fprintf('For Confidence interval %1.2f\n',Beta);
        tt=1;
        for N=0.15:0.025:0.40
            pf_corr =0;
            Pabnorm=0;
             
            % neighbourhood SU user prediction using Correlation estimation
            L=Nmina(tt);
            for t=1:L
                for i = 1:M
                    for j = 1:M
                        if i<= j
                            R_corr(i,j) = p_corr^(j-i);
                        elseif i>j
                            R_corr(i,j) = conj(R_corr(j,i));
                        end
                    end
                end
               
                var_h = 1;
                var_n = var(rand(1,M));
                P = 10^(dBSNR(tt)/10);
                %under condition H0 only noise is present
                mean_H0 = N*M*var_n;
                var_H0 = N*M*var_n^2;
                decision_statistic_H0 = sqrt(var_H0)*randn(1,1) + mean_H0;
                %unser condition H1 signal and noise both are present
                mean_H1 = N*M*(P*var_h + var_n);
                var_H1_corr = 0;
                lambda_corr = eig(R_corr);
                %kernel density estimation Eq(7)
                for k =1:M
                    var_H1_corr = var_H1_corr + (P*var_h*lambda_corr(k) + var_n)^2;
                end
                var_H1_corr = var_H1_corr*N;
                decision_statistic_H1_corr = sqrt(var_H1_corr)*randn(1,1) + mean_H1;
                Confidence_interval = 0;
                % standard gaussian distribution
                for l=1:M
                    Confidence_interval = Confidence_interval  + (P*var_h*lambda_corr(l) + var_n)^2;
                end
                 tcorr = sqrt(Confidence_interval*N);
                 % confidence interval Eq(8)
                 Confid_interval = abs(abs(qfuncinv(Beta)*tcorr)-N*M*(P*var_h + var_n));
                 if (decision_statistic_H0 >= Confid_interval)
                     pf_corr = pf_corr + 1;
                 else
                     Pabnorm=Pabnorm+1;
                 end
            end
            pff_corr(tt) = pf_corr/L;
            pdd_corr(tt) = 1-(pf_corr/L);
             tt=tt+1;
        end
        Pbeta(:,jB)=pdd_corr;
        jB=jB+1;
       
    end
    
    N=0.15:0.025:0.40;
    figure(3);
    plot(N,sort(Pbeta,'descend'),'o-');
    grid on;
    ylabel('Success Probability');
    xlabel('Percentage of malicious user');
    legend('Beta=0.025','Beta=0.05','Beta=0.075','Beta=0.1');
    title('N=20');

 disp('========== Performance for Different Number of Secondary users vs beta===========');
    jS=1;
    dBSNR = -10:0;

    for M = 5:20:45
        fprintf('For Secondary User %d\n',M);
        tt=1;
        for Beta = 0.025:0.0125:0.15
            pf_corr =0;
            Pabnorm =0;
            % neighbourhood SU user prediction using Correlation estimation
            L=Nmina(tt);
            for t=1:L
                for i = 1:M
                    for j=1:M
                        if i<= j
                            R_corr(i,j) = p_corr^(j-i);
                        elseif i>j
                            R_corr(i,j) = conj(R_corr(j,i));
                        end
                    end
                end
                N=0.15;
                var_h = 1;
                var_n = var(rand(1,M));
                P = 10^(dBSNR(tt)/10);
                mean_H0 = N*M*var_n;
                var_H0 = N*M*var_n^2;
                decision_statistics_H0 = sqrt(var_H0)*randn(1,1) + mean_H0;
                % under condition H1 signal and noise botha re present 
                mean_H1=N*M*(P*var_h+var_n);
                var_H1_corr=0;
                lambda_corr=eig(R_corr);
                alpha=0.1;
                %kernel density estimator Eq(7)
                for k=1:M
                    var_H1_corr=var_H1_corr+(P*var_h*lambda_corr(k)+var_n)^2;
                end 
                var_H1_corr= var_H1_corr*N;
                decision_statistics_H1_corr=sqrt(var_H1_corr)*randn(1,1)+mean_H1;
                Confidence_interval=0;
                % standard gaussian distribution
                for l=1:M
                    Confidence_interval = Confidence_interval + (P*var_h*lambda_corr(l) + var_n)^2;
                end
                tcorr=sqrt(Confidence_interval*N);
                % confidence interval Eq(8)
                Confid_interval=abs(abs(qfuncinv(alpha)*tcorr)-N*M*(P*var_h+var_n));
                if (decision_statistics_H0 >= Confid_interval)
                    pf_corr=pf_corr+1;
                else
                    Pabnorm=Pabnorm+1;
                end
            end
            pff_corr(tt)=pf_corr/L;
            pdd_corr(tt)=1-(pf_corr/L);
           tt=tt+1;
        end
        PSuser1(:,jS)=pdd_corr;
        jS=jS+1;
        
    end
    Beta = 0.025:0.0125:0.15 ;
    figure(1);
    plot(Beta,PSuser1,'o-'); 
    grid on;
    xlim([0.025 0.125]);
    ylabel('success probaility');
    xlabel('Beta value');
    legend('user=10','user=30','user=50');
    title('Malicous user =15%')

dBSNR=-13:1:-3;
 disp('========== Performance for Different Number of Secondary users vs beta ===========');
    jP=1;
    for N=0.15:0.05:0.25
        fprintf('For Secondary User %d\n',M);
        tt=1;
        for M=10:5:60
            pf_corr =0;
            Pabnorm =0;
            % neighbourhood SU user prediction using Correlation estimation
            L=Nmina(tt);
            for t=1:L
                for i = 1:M
                    for j=1:M
                        if i<= j
                            R_corr(i,j) = p_corr^(j-i);
                        elseif i>j
                            R_corr(i,j) = conj(R_corr(j,i));
                        end
                    end
                end
      
                var_h = 1;
                var_n = var(rand(1,M));
                P = 10^(dBSNR(tt)/10);
                mean_H0 = N*M*var_n;
                var_H0 = N*M*var_n^2;
                decision_statistics_H0 = sqrt(var_H0)*randn(1,1) + mean_H0;
                % under condition H1 signal and noise botha re present 
                mean_H1=N*M*(P*var_h+var_n);
                var_H1_corr=0;
                lambda_corr=eig(R_corr);
                alpha=0.1;
                %kernel density estimator Eq(7)
                for k=1:M
                    var_H1_corr=var_H1_corr+(P*var_h*lambda_corr(k)+var_n)^2;
                end 
                var_H1_corr= var_H1_corr*N;
                decision_statistics_H1_corr=sqrt(var_H1_corr)*randn(1,1)+mean_H1;
                Confidence_interval=0;
                % standard gaussian distribution
                for l=1:M
                    Confidence_interval = Confidence_interval + (P*var_h*lambda_corr(l) + var_n)^2;
                end
                tcorr=sqrt(Confidence_interval*N);
                % confidence interval Eq(8)
                Confid_interval=abs(abs(qfuncinv(alpha)*tcorr)-N*M*(P*var_h+var_n));
                if (decision_statistics_H0 >= Confid_interval)
                    pf_corr=pf_corr+1;
                else
                    Pabnorm=Pabnorm+1;
                end
            end
            pff_corr(tt)=pf_corr/L;
            pdd_corr(tt)=1-(pf_corr/L);
           tt=tt+1;
        end
        PSuser2(:,jP)=pdd_corr;
        jP=jP+1;
        
    end
     M=10:5:60;
    figure(5);
    plot(M,PSuser2,'o-'); 
    grid on;
    ylabel('success probability');
    xlabel('no of secondary users');
    legend('Malicious 15%','Malicious 20%','Malicious 25%');
    title('Beta=0.1')