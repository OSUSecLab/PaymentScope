import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;

class MyInst {
		Function func;
		HighFunction highFunc;
		PcodeOpAST op;
		
		public MyInst(Function func, HighFunction highFunc, PcodeOpAST op) {
			super();
			this.func = func;
			this.highFunc = highFunc;
			this.op = op;
		}

		public Function getFunc() {
			return func;
		}

		public void setFunc(Function func) {
			this.func = func;
		}

		public HighFunction getHighFunc() {
			return highFunc;
		}

		public void setHighFunc(HighFunction highFunc) {
			this.highFunc = highFunc;
		}

		public PcodeOpAST getOp() {
			return op;
		}

		public void setOp(PcodeOpAST op) {
			this.op = op;
		}
		
		
		
	}
