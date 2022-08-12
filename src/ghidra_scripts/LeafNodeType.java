
public enum LeafNodeType {
	MAX_DEPTH("MAX_DEPTH"), MAX_ID("MAX_ID"), Unkown_API("Unkown_API"), Unkown_OPCode("Unkown_OPCode"),
	Unhandlable_OPCode("Unhandlable_OPCode"), Ending_OPCode("Ending_OPCode"), Ending_API("Ending_API"),
	Unused_Parameter("Unused_Parameter"), Unused_Node("Unused_Node"), Missing_Target_Node("Missing_Target_Node"),
	No_Callser("No_Callser");

	// Unity_API("Unity_API"),

	private String name;

	private LeafNodeType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
}