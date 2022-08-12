public class FieldResolutionReport {
	String hostClass = null;
	int offset = -1;
	String errorMsg = null;
	
	public String toString() {
		return String.format("hostClass:%s / offset:%s / errorMsg:%s", hostClass, offset, errorMsg);
	}
}