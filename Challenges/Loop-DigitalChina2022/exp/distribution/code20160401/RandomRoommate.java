import java.util.*;

public class RandomRoommate { 

    static int n;
    static double p;
    static Random gen;
    static boolean[][] A;

    static void shuffle(int[] v,int n){
	int j, temp;
	for (int i=n-1;i>0;i--){
	    j = gen.nextInt(i+1);
	    temp = v[i];
	    v[i] = v[j];
	    v[j] = temp;
	}
    }
  
    public static void main(String[] args) throws Exception {
	n       = Integer.parseInt(args[0]);
	p       = 1.0; 
	A       = new boolean[n][n];
	gen     = new Random();
	int[] v = new int[n];
	if (args.length == 2) p = Double.parseDouble(args[1]);
	System.out.println(n);
	for (int i=0;i<n-1;i++)
	    for (int j=i+1;j<n;j++)
		if (p >= gen.nextDouble())
		    A[i][j] = A[j][i] = true; // i and j rank each other
	for (int i=0;i<n;i++){
	    int k=0;
	    for (int j=0;j<n;j++) if (A[i][j]) v[k++] = j;
	    shuffle(v,k);
	    for (int j=0;j<k;j++) System.out.print((v[j]+1) +" ");
	    System.out.println();
	}
    }
}
