#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::ento;

namespace {
class MyChecker final : public Checker<check::EndOfTranslationUnit>, public MatchFinder::MatchCallback {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				 AnalysisManager &A, BugReporter &BR) const;
  void run(const MatchFinder::MatchResult &res);
};
}

void MyChecker::run(const MatchFinder::MatchResult &res)
{
	if (auto RD = res.Nodes.getNodeAs<RecordDecl>("RD")) {
		llvm::errs() << "RD:\n";
		RD->dumpColor();
	}
	if (auto ME = res.Nodes.getNodeAs<MemberExpr>("ME")) {
		llvm::errs() << "ME:\n";
		ME->dumpColor();
	}
	if (auto BO = res.Nodes.getNodeAs<BinaryOperator>("BO")) {
		llvm::errs() << "BO:\n";
		BO->dumpColor();
	}
}

void MyChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
					  AnalysisManager &A,
					  BugReporter &BR) const
{
	TU->dumpColor();

	auto me = const_cast<MyChecker *>(this);
	MatchFinder F;

	F.addMatcher(recordDecl(isStruct()).bind("RD"), me);
	F.addMatcher(memberExpr().bind("ME"), me);
	F.addMatcher(binaryOperator().bind("BO"), me);

	F.matchAST(A.getASTContext());
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<MyChecker>("jirislaby.PoBug", "XXX", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
