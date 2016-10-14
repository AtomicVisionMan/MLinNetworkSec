function ALO_optim()
SearchAgents_no=30; % Number of search agents
Function_name='F1'; % Name of the test function 
Max_iteration=100; % Maximum numbef of iterations

% Load details of the selected benchmark function
        fobj = @F1;
        lb=-100;
        ub=100;
        dim=5;

[Best_score,Best_pos,cg_curve]=ALO(SearchAgents_no,Max_iteration,lb,ub,dim,fobj);

end