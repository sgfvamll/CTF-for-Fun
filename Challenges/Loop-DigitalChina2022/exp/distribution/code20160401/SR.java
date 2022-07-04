//
// Toolkit constraint encoding
//
import java.io.*;
import java.util.*;
import static choco.Choco.*;
import choco.cp.model.CPModel;
import choco.cp.solver.CPSolver;
import choco.kernel.model.Model;
import choco.kernel.solver.Solver;
import choco.kernel.model.variables.integer.IntegerVariable;
import choco.kernel.solver.variables.integer.IntDomainVar;
import choco.kernel.solver.ContradictionException;
import choco.cp.solver.search.integer.varselector.StaticVarOrder;

public class SR {	
   
    int n;
    int[][] rank; // rank[i][j] = k <-> agent_i ranks agent_j as k^th choice
    int[][] pref; // pref[i][k] = j <-> agent_i has agent_j as k^th choice
    int[] length; // length of agent's preference list
    Model model;
    Solver solver;
    IntegerVariable[] agent; // domain of ranks, last is unmatched
    long totalTime, modelTime, solveTime, readTime, modelSize;
    boolean search;
    int solutions, matchingSize;

    SR(String fname) throws IOException {
	search      = true;
	totalTime   = System.currentTimeMillis();
	readTime    = System.currentTimeMillis();
	read(fname);
	readTime = System.currentTimeMillis() - readTime; 
    }

    SR(SMSRInstance inst) {
	search      = true;
	totalTime   = System.currentTimeMillis();
	readTime    = System.currentTimeMillis();
	read(inst);
	readTime = System.currentTimeMillis() - readTime; 
    }

    void read(String fname) throws IOException {
	BufferedReader fin = new BufferedReader(new FileReader(fname));
	n                  = Integer.parseInt(fin.readLine());
	pref               = new int[n][n]; 
	rank               = new int[n][n]; 
	length             = new int[n];
	for (int i=0;i<n;i++){
	    StringTokenizer st = new StringTokenizer(fin.readLine()," ");
	    int k = 0;
	    length[i] = 0;
	    while (st.hasMoreTokens()){
		int j      = Integer.parseInt(st.nextToken()) - 1;
		rank[i][j] = k;
		pref[i][k] = j;
		length[i]  = length[i] + 1;
		k          = k + 1;
	    }
	    rank[i][i] = k;
	    pref[i][k] = i;
	}
	fin.close();
    }	

    void read(SMSRInstance inst) {
	n                  = inst.n;
	pref               = new int[n][n]; 
	rank               = new int[n][n]; 
	length             = new int[n];
	for (int i=0;i<n;i++){
	    int k = 0;
	    length[i] = 0;
	    for (int j : (ArrayList<Integer>)inst.pref[i]){
		rank[i][j] = k;
		pref[i][k] = j;
		length[i]  = length[i] + 1;
		k          = k + 1;
	    }
	    rank[i][i] = k;
	    pref[i][k] = i;
	}
    }	

    void build(){
	modelTime = System.currentTimeMillis();
	model     = new CPModel(); 
	agent     = new IntegerVariable[n];
	for (int i=0;i<n;i++) agent[i] = makeIntVar("agent_"+ i,0,length[i],"cp:enum");
	for (int i=0;i<n;i++)
	    for (int j=0;j<length[i];j++){
		int k = pref[i][j];
		model.addConstraint(implies(gt(agent[i],rank[i][k]),lt(agent[k],rank[k][i])));
		model.addConstraint(implies(eq(agent[i],rank[i][k]),eq(agent[k],rank[k][i])));
	    }
	solver     = new CPSolver(); 
	solver.read(model); 
	modelTime  = System.currentTimeMillis() - modelTime;
	modelSize  = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())/1024; // kilobytes
    }

    void solve(String command) throws ContradictionException {
	solutions = matchingSize = 0;
	solveTime = System.currentTimeMillis();
	solver.setVarIntSelector(new StaticVarOrder(solver,solver.getVar(agent)));
	if (command.equals("count")){ // count all solutions
	    solver.solve(true);
	    solutions = solver.getNbSolutions();
	    if (solutions > 0) getMatchingSize();
	}
	else if (command.equals("all")){ // enumerate all solutions
	    if (solver.solve().booleanValue()){
		getMatchingSize();
		displayMatching();
		solutions = 1;
		while (solver.nextSolution().booleanValue()){solutions++; displayMatching();}
	    }
	}
	else if (command.equals("propagate")){
	    search = false;
	    solver.propagate();
	    try{solver.propagate(); displayPhase1Table();} catch (ContradictionException e){displayPhase1Table();}
	}
	else if (solver.solve().booleanValue()){
	    solutions = 1;
	    getMatchingSize();
	    displayMatching();
	}
	solveTime = System.currentTimeMillis() - solveTime;
	totalTime = System.currentTimeMillis() - totalTime;
    }

    int getMatchingSize(){
	matchingSize = 0;
	for (int i=0;i<n;i++)
	    if (solver.getVar(agent[i]).getVal() < length[i]) matchingSize++;
	matchingSize = matchingSize/2;
	return matchingSize;
    }

    void displayMatching(){
	for (int i=0;i<n;i++){
	    int j = pref[i][solver.getVar(agent[i]).getVal()];
	    if (i<j) System.out.print("("+ (i+1) +","+ (j+1) +") ");
	}
	System.out.println();
    }

    void displayPhase1Table(){
	for (int i=0;i<n;i++){
	    IntDomainVar v = solver.getVar(agent[i]);
	    System.out.print(i+1 +": ");
	    for (int j=0;j<n;j++) if (v.getDomain().contains(j)) System.out.print(pref[i][j]+1 +" ");
	    System.out.println();
	}
    }

    void display(){
	System.out.println(n);
	for (int i=0;i<n;i++){
	    for (int j=0;j<n;j++)
		if (pref[i][j] != i) System.out.print((pref[i][j] + 1) +" ");
	    System.out.println();
	}
    }	    

    void stats(){
	System.out.print("solutions: "+ solutions +" ");
	if (search) System.out.print("nodes: "+ solver.getNodeCount() +"  ");
	System.out.print("modelTime: "+ modelTime +"  ");
	if (search) System.out.print("solveTime: "+ solveTime +"  ");
	System.out.print("totalTime: "+ totalTime +"  ");
	System.out.print("modelSize: "+ modelSize +"  ");
	System.out.print("readTime: "+ readTime +" ");
	System.out.print("matchingSize: "+ matchingSize);
	System.out.println();
    }

    public static void main(String[] args) throws IOException, ContradictionException {
	SR sr = new SR(args[0]);
	sr.build();
	if (args.length > 1) 
	    sr.solve(args[1]);
	else
	    sr.solve("first");
	sr.stats();
    }
}
