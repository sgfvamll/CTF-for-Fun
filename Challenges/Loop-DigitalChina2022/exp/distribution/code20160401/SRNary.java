//
// uses the n-ary constraint proposed by Prosser & Unsworth IJCAI2005
//
import java.io.*;
import java.util.*;
import static choco.Choco.*;
import choco.cp.model.CPModel;
import choco.cp.solver.CPSolver;
import choco.kernel.model.Model;
import choco.kernel.solver.Solver;
import choco.kernel.model.variables.integer.IntegerVariable;
import choco.kernel.solver.ContradictionException;

public class SRNary extends SR {	

    SRNary(String fname) throws IOException {super(fname);}

    SRNary(SMSRInstance inst){super(inst);}

    void build(){
	modelTime = System.currentTimeMillis();
	model     = new CPModel(); 
	agent     = new IntegerVariable[n];
	for (int i=0;i<n;i++) agent[i] = makeIntVar("agent_"+ i,0,length[i],"cp:enum");
	model.addVariables(agent);
	solver    = new CPSolver(); 
	solver.read(model); 
	solver.post(new SRN(solver,solver.getVar(agent),pref,rank,length));
	modelTime  = System.currentTimeMillis() - modelTime;
	modelSize  = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())/1024; // kilobytes
    }

    
    public static void main(String[] args) throws IOException, ContradictionException {
	SRNary sr = new SRNary(args[0]);
	sr.build();
	if (args.length > 1) 
	    sr.solve(args[1]);
	else
	    sr.solve("first");
	sr.stats();
    }
}
