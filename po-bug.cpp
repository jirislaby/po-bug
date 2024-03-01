#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::ento;

namespace {
class MyChecker final : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				 AnalysisManager &A, BugReporter &BR) const;
};

class MatchCallback : public MatchFinder::MatchCallback {
public:
	MatchCallback() {}

	void run(const MatchFinder::MatchResult &res);
private:
};
}

void MatchCallback::run(const MatchFinder::MatchResult &res)
{
	if (auto RD = res.Nodes.getNodeAs<RecordDecl>("RD")) {
		llvm::errs() << "RD:\n";
		RD->dumpColor();
	}
	if (auto ME = res.Nodes.getNodeAs<MemberExpr>("ME")) {
		llvm::errs() << "ME:\n";
		ME->dumpColor();
	}
	if (auto ME = res.Nodes.getNodeAs<MemberExpr>("MESTORE")) {
		llvm::errs() << "MESTORE:\n";
		ME->dumpColor();
	}
}

void MyChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
					  AnalysisManager &A,
					  BugReporter &BR) const
{
	TU->dumpColor();

	MatchFinder F;
	MatchCallback CB;
	F.addMatcher(traverse(TK_IgnoreUnlessSpelledInSource, recordDecl(isStruct()).bind("RD")), &CB);
	F.addMatcher(traverse(TK_IgnoreUnlessSpelledInSource, memberExpr().bind("ME")), &CB);
	F.addMatcher(traverse(TK_IgnoreUnlessSpelledInSource,
			      binaryOperator(isAssignmentOperator(),
					     hasLHS(memberExpr().bind("MESTORE")))), &CB);

	F.matchAST(A.getASTContext());
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<MyChecker>("jirislaby.PoBug", "XXX", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
