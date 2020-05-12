import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {

	private LoadGenerator generator;
	
	public Generator()
	{
		Task work = new ClientServerTask();
		int numberOfTasks = 400;
		int gapBetweenTaks = 20;
		generator = new LoadGenerator("Client - Server Load Test", numberOfTasks, work, gapBetweenTaks);
		generator.generate();
	}
	
	public static void main(String[] args){
		
		@SuppressWarnings("unused")
		Generator gen = new Generator();
	}
}
