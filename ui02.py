import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from decimal import Decimal
import uuid

# ==================== ENUMS ====================
class DebtStatus(Enum):
    ACTIVE = "ACTIVE"
    SETTLED = "SETTLED"

# ==================== RESULT CLASS ====================
class Result:
    """Represents operation result - Success or Failure"""
    def __init__(self, success: bool, message: str = "", data=None):
        self.success = success
        self.message = message
        self.data = data
    
    @staticmethod
    def ok(data=None):
        """Success result"""
        return Result(True, "", data)
    
    @staticmethod
    def error(message: str):
        """Error result"""
        return Result(False, message)
    
    def is_success(self) -> bool:
        return self.success

# ==================== SPLIT STRATEGY ====================
class SplitMethod(ABC):
    @abstractmethod
    def calculate_shares(self, total_amount: Decimal, participants: List['User']) -> Dict['User', Decimal]:
        pass

class EqualSplit(SplitMethod):
    def calculate_shares(self, total_amount: Decimal, participants: List['User']) -> Dict['User', Decimal]:
        if len(participants) == 0:
            return {}
        share = total_amount / len(participants)
        return {user: share for user in participants}

class PercentageSplit(SplitMethod):
    def __init__(self):
        self.percentages = {}
    
    def set_percentages(self, percentages: Dict['User', float]) -> Result:
        """Set percentages and validate - returns Result instead of raising exception"""
        if not percentages:
            return Result.error("❌ No percentages set!")
        
        self.percentages = percentages
        
        # Validate
        total_percentage = sum(self.percentages.values())
        if abs(total_percentage - 100.0) > 0.01:
            return Result.error(
                f"❌ Total percentage is {total_percentage:.2f}%, but should be 100%!"
            )
        
        return Result.ok()
    
    def calculate_shares(self, total_amount: Decimal, participants: List['User']) -> Dict['User', Decimal]:
        shares = {}
        for user in participants:
            if user in self.percentages:
                shares[user] = total_amount * Decimal(str(self.percentages[user] / 100))
            else:
                shares[user] = Decimal(0)
        return shares

class UnequalSplit(SplitMethod):
    def __init__(self):
        self.custom_amounts = {}
    
    def set_custom_amounts(self, custom_amounts: Dict['User', Decimal], total_amount: Decimal) -> Result:
        """Set amounts and validate - returns Result"""
        if not custom_amounts:
            return Result.error("❌ No custom amounts set!")
        
        # Check for negative values
        for user, amount in custom_amounts.items():
            if amount < 0:
                return Result.error(f"❌ Amount for {user.name} cannot be negative!")
        
        # Check if sum matches total
        custom_total = sum(custom_amounts.values())
        if custom_total != total_amount:
            return Result.error(
                f"❌ Sum of amounts (${custom_total:.2f}) doesn't match total (${total_amount:.2f})!"
            )
        
        self.custom_amounts = custom_amounts
        return Result.ok()
    
    def calculate_shares(self, total_amount: Decimal, participants: List['User']) -> Dict['User', Decimal]:
        return self.custom_amounts.copy()

# ==================== DEBT & LEDGER ====================
class Debt:
    def __init__(self, debtor: 'User', creditor: 'User', amount: Decimal):
        self.debt_id = str(uuid.uuid4())
        self.debtor = debtor
        self.creditor = creditor
        self.amount = amount
        self.status = DebtStatus.ACTIVE
        self.created_at = datetime.now()
        self.settled_at = None
    
    def settle(self):
        self.status = DebtStatus.SETTLED
        self.settled_at = datetime.now()
    
    def get_details(self) -> str:
        return f"{self.debtor.name} owes {self.creditor.name}: ${self.amount:.2f}"

class DebtLedger:
    def __init__(self, group_id: str):
        self.group_id = group_id
        self.debts: List[Debt] = []
    
    def add_debt(self, debtor: 'User', creditor: 'User', amount: Decimal):
        debt = Debt(debtor, creditor, amount)
        self.debts.append(debt)
        return debt
    
    def get_debt(self, debtor: 'User', creditor: 'User') -> Decimal:
        total = Decimal(0)
        for debt in self.debts:
            if debt.debtor == debtor and debt.creditor == creditor and debt.status == DebtStatus.ACTIVE:
                total += debt.amount
        return total
    
    def get_net_debt(self, user1: 'User', user2: 'User') -> Tuple[str, Decimal]:
        debt_1_to_2 = self.get_debt(user1, user2)  # How much user1 owes user2
        debt_2_to_1 = self.get_debt(user2, user1)  # How much user2 owes user1
        
        # Net from user2's perspective (who owes whom from user2's view)
        net = debt_2_to_1 - debt_1_to_2
        
        if net > 0:
            return f"{user1.name} owes {user2.name}: ${net:.2f}", net
        elif net < 0:
            return f"{user2.name} owes {user1.name}: ${abs(net):.2f}", abs(net)
        else:
            return f"{user1.name} and {user2.name} are even", Decimal(0)
    
    def simplify_debts(self) -> Dict[Tuple[str, str], Decimal]:
        simplified = {}
        users = set()
        for debt in self.debts:
            if debt.status == DebtStatus.ACTIVE:
                users.add(debt.debtor)
                users.add(debt.creditor)
        
        users = list(users)
        for i, user1 in enumerate(users):
            for user2 in users[i+1:]:
                # Always call with debtor first, then creditor
                # Check who actually owes whom
                debt_1_to_2 = self.get_debt(user1, user2)  # user1 owes user2
                debt_2_to_1 = self.get_debt(user2, user1)  # user2 owes user1
                
                # Calculate net: what user2 owes user1 minus what user1 owes user2
                net = debt_2_to_1 - debt_1_to_2
                
                if net > 0:
                    # user1 owes user2 nothing, user2 owes user1
                    simplified[(user2.name, user1.name)] = net
                elif net < 0:
                    # user2 owes user1 nothing, user1 owes user2
                    simplified[(user1.name, user2.name)] = abs(net)
        
        return simplified
    
    def settle_debt(self, debtor: 'User', creditor: 'User', amount: Decimal):
        for debt in self.debts:
            if debt.debtor == debtor and debt.creditor == creditor and debt.status == DebtStatus.ACTIVE:
                if debt.amount <= amount:
                    debt.settle()
                    amount -= debt.amount
                    if amount == 0:
                        break
                else:
                    debt.amount -= amount
                    break

# ==================== USER & EXPENSE ====================
class User:
    def __init__(self, name: str, email: str):
        self.user_id = str(uuid.uuid4())
        self.name = name
        self.email = email
        self.friends: List['User'] = []
    
    def add_friend(self, friend: 'User'):
        if friend not in self.friends:
            self.friends.append(friend)
    
    def __eq__(self, other):
        if isinstance(other, User):
            return self.user_id == other.user_id
        return False
    
    def __hash__(self):
        return hash(self.user_id)
    
    def __repr__(self):
        return self.name

class Expense:
    def __init__(self, group: 'Group', description: str, total_amount: Decimal, 
                 payer: User, participants: List[User], split_method: SplitMethod):
        self.expense_id = str(uuid.uuid4())
        self.group = group
        self.description = description
        self.total_amount = total_amount
        self.payer = payer
        self.participants = participants
        self.split_method = split_method
        self.created_at = datetime.now()
    
    def calculate_shares(self) -> Dict[User, Decimal]:
        return self.split_method.calculate_shares(self.total_amount, self.participants)
    
    def apply_to_ledger(self, ledger: DebtLedger):
        shares = self.calculate_shares()
        for user, amount in shares.items():
            if user != self.payer and amount > 0:
                ledger.add_debt(user, self.payer, amount)
    
    def get_details(self) -> str:
        shares = self.calculate_shares()
        details = f"Expense: {self.description} | Total: ${self.total_amount:.2f} | Payer: {self.payer.name}\n"
        details += "Shares: " + ", ".join([f"{u.name}: ${a:.2f}" for u, a in shares.items()])
        return details

class GroupMember:
    def __init__(self, user: User, group: 'Group', role: str = "MEMBER"):
        self.member_id = str(uuid.uuid4())
        self.user = user
        self.group = group
        self.role = role
        self.joined_at = datetime.now()

class Group:
    def __init__(self, name: str, description: str, owner: User, is_friend_group: bool = False):
        self.group_id = str(uuid.uuid4())
        self.group_name = name
        self.description = description
        self.owner = owner
        self.members: List[GroupMember] = []
        self.expenses: List[Expense] = []
        self.debt_ledger = DebtLedger(self.group_id)
        self.is_friend_group = is_friend_group
        self.created_at = datetime.now()
        self.add_member(owner, "OWNER")
    
    def add_member(self, user: User, role: str = "MEMBER"):
        if not any(m.user == user for m in self.members):
            member = GroupMember(user, self, role)
            self.members.append(member)
    
    def add_expense(self, expense: Expense):
        self.expenses.append(expense)
        expense.apply_to_ledger(self.debt_ledger)
    
    def get_simplified_debts(self) -> Dict[Tuple[str, str], Decimal]:
        return self.debt_ledger.simplify_debts()

# ==================== VALIDATION SERVICE ====================
class ValidationService:
    """Centralized validation logic"""
    
    @staticmethod
    def validate_group_creation(name: str, description: str) -> Result:
        if not name or not name.strip():
            return Result.error("❌ Group name cannot be empty!")
        return Result.ok()
    
    @staticmethod
    def validate_friend_creation(name: str, email: str) -> Result:
        if not name or not name.strip():
            return Result.error("❌ Name cannot be empty!")
        if not email or not email.strip():
            return Result.error("❌ Email cannot be empty!")
        return Result.ok()
    
    @staticmethod
    def validate_expense_input(description: str, amount_str: str, payer_name: str, 
                              participants: list) -> Result:
        if not description or not description.strip():
            return Result.error("❌ Description cannot be empty!")
        
        try:
            amount = Decimal(amount_str)
            if amount <= 0:
                return Result.error("❌ Amount must be greater than 0!")
        except:
            return Result.error("❌ Invalid amount entered!")
        
        if not payer_name:
            return Result.error("❌ Please select a payer!")
        
        if not participants:
            return Result.error("❌ Please select at least one participant!")
        
        return Result.ok(amount)

# ==================== TKINTER UI ====================
class SplitSmartUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SplitSmart - Fast Testing UI")
        self.root.geometry("900x700")
        
        self.current_user = User("Alice", "alice@example.com")
        self.users: List[User] = [self.current_user]
        self.groups: List[Group] = []
        
        self.validator = ValidationService()
        
        self.setup_test_data()
        self.create_ui()
    
    def setup_test_data(self):
        """Create test users and groups for quick testing"""
        bob = User("Bob", "bob@example.com")
        charlie = User("Charlie", "charlie@example.com")
        self.users.extend([bob, charlie])
        
        self.current_user.add_friend(bob)
        self.current_user.add_friend(charlie)
    
    def create_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        title = ttk.Label(main_frame, text="🏦 SplitSmart - Fast Testing", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        user_info = ttk.Label(main_frame, text=f"Current User: {self.current_user.name}", font=("Arial", 10))
        user_info.pack()
        
        button_frame = ttk.LabelFrame(main_frame, text="Quick Actions", padding=10)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="➕ Create Group", command=self.show_create_group).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="👥 Add Friend", command=self.show_add_friend).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📋 View Groups", command=self.show_groups).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="👫 View Friends", command=self.show_friends).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💳 View All Debts", command=self.show_all_debts).pack(side=tk.LEFT, padx=5)
        
        self.output_frame = ttk.LabelFrame(main_frame, text="Output", padding=10)
        self.output_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(self.output_frame, height=25, width=100, state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        self.print_output("Welcome to SplitSmart Testing UI!\nSelect an action from above.")
    
    def print_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text + "\n" + "="*80 + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def show_create_group(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Create Group")
        dialog.geometry("400x250")
        
        ttk.Label(dialog, text="Group Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=30)
        name_entry.pack()
        
        ttk.Label(dialog, text="Description:").pack(pady=5)
        desc_entry = ttk.Entry(dialog, width=30)
        desc_entry.pack()
        
        ttk.Label(dialog, text="Select Members:").pack(pady=5)
        
        var_frame = ttk.Frame(dialog)
        var_frame.pack()
        
        selected_members = []
        for user in self.users:
            if user != self.current_user:
                var = tk.BooleanVar()
                ttk.Checkbutton(var_frame, text=user.name, variable=var, 
                              command=lambda u=user, v=var: self.toggle_member(selected_members, u, v)).pack(anchor=tk.W)
        
        def create():
            name = name_entry.get()
            desc = desc_entry.get()
            
            result = self.validator.validate_group_creation(name, desc)
            if not result.is_success():
                messagebox.showerror("Validation Error", result.message)
                return
            
            group = Group(name, desc, self.current_user)
            for member in selected_members:
                group.add_member(member)
            self.groups.append(group)
            
            self.print_output(f"✅ Group '{name}' created with members: {', '.join([m.user.name for m in group.members])}")
            dialog.destroy()
        
        ttk.Button(dialog, text="Create", command=create).pack(pady=10)
    
    def toggle_member(self, selected_members, user, var):
        if var.get():
            if user not in selected_members:
                selected_members.append(user)
        else:
            if user in selected_members:
                selected_members.remove(user)
    
    def show_add_friend(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Friend")
        dialog.geometry("300x200")
        
        ttk.Label(dialog, text="Friend Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=30)
        name_entry.pack()
        
        ttk.Label(dialog, text="Friend Email:").pack(pady=5)
        email_entry = ttk.Entry(dialog, width=30)
        email_entry.pack()
        
        def add():
            name = name_entry.get()
            email = email_entry.get()
            
            result = self.validator.validate_friend_creation(name, email)
            if not result.is_success():
                messagebox.showerror("Validation Error", result.message)
                return
            
            new_friend = User(name, email)
            self.current_user.add_friend(new_friend)
            self.users.append(new_friend)
            
            self.print_output(f"✅ {name} added to friends!")
            dialog.destroy()
        
        ttk.Button(dialog, text="Add", command=add).pack(pady=10)
    
    def show_groups(self):
        if not self.groups:
            self.print_output("❌ No groups yet!")
            return
        
        output = "📋 YOUR GROUPS:\n"
        for idx, group in enumerate(self.groups, 1):
            group_type = "👥 Friend" if group.is_friend_group else "📋 Regular"
            output += f"\n{idx}. {group.group_name} ({group_type})\n"
            output += f"   Members: {', '.join([m.user.name for m in group.members])}\n"
            output += f"   Expenses: {len(group.expenses)}\n"
        
        self.print_output(output)
        self.show_group_details_dialog()
    
    def show_group_details_dialog(self):
        if not self.groups:
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Group")
        dialog.geometry("400x300")
        
        ttk.Label(dialog, text="Select a group:").pack(pady=10)
        
        group_var = tk.StringVar()
        group_combo = ttk.Combobox(dialog, textvariable=group_var, 
                                   values=[f"{i}. {g.group_name}" for i, g in enumerate(self.groups, 1)],
                                   state="readonly")
        group_combo.pack(pady=5, padx=10, fill=tk.X)
        
        def open_group():
            if not group_var.get():
                messagebox.showerror("Error", "Select a group!")
                return
            idx = int(group_var.get().split(".")[0]) - 1
            self.show_group_menu(self.groups[idx])
            dialog.destroy()
        
        ttk.Button(dialog, text="Open", command=open_group).pack(pady=10)
    
    def show_group_menu(self, group):
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Group: {group.group_name}")
        dialog.geometry("500x400")
        
        ttk.Label(dialog, text=f"Group: {group.group_name}", font=("Arial", 12, "bold")).pack(pady=10)
        ttk.Label(dialog, text=f"Members: {', '.join([m.user.name for m in group.members])}").pack()
        ttk.Label(dialog, text=f"Expenses: {len(group.expenses)}").pack(pady=10)
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="➕ Add Expense", 
                  command=lambda: self.show_add_expense_dialog(dialog, group)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💳 View Debts", 
                  command=lambda: self.show_group_debts(group)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📋 View Expenses", 
                  command=lambda: self.show_group_expenses(group)).pack(side=tk.LEFT, padx=5)
    
    def show_add_expense_dialog(self, parent, group):
        dialog = tk.Toplevel(parent)
        dialog.title("Add Expense")
        dialog.geometry("500x750")
        
        ttk.Label(dialog, text="Description:").pack(pady=5)
        desc_entry = ttk.Entry(dialog, width=30)
        desc_entry.pack()
        
        ttk.Label(dialog, text="Amount ($):").pack(pady=5)
        amount_entry = ttk.Entry(dialog, width=30)
        amount_entry.pack()
        
        ttk.Label(dialog, text="Payer:").pack(pady=5)
        payer_var = tk.StringVar()
        payer_combo = ttk.Combobox(dialog, textvariable=payer_var, 
                                   values=[m.user.name for m in group.members],
                                   state="readonly")
        payer_combo.pack(pady=5, padx=10, fill=tk.X)
        
        ttk.Label(dialog, text="Participants:").pack(pady=5)
        
        selected_participants = []
        participant_vars = {}
        for member in group.members:
            var = tk.BooleanVar()
            participant_vars[member.user] = var
            ttk.Checkbutton(dialog, text=member.user.name, variable=var,
                          command=lambda u=member.user, v=var: self.toggle_member(selected_participants, u, v)).pack(anchor=tk.W, padx=20)
        
        ttk.Label(dialog, text="Split Method:").pack(pady=10)
        split_var = tk.StringVar(value="Equal")
        ttk.Radiobutton(dialog, text="Equal Split", variable=split_var, value="Equal").pack(anchor=tk.W, padx=20)
        ttk.Radiobutton(dialog, text="Percentage Split", variable=split_var, value="Percentage").pack(anchor=tk.W, padx=20)
        ttk.Radiobutton(dialog, text="Unequal Split", variable=split_var, value="Unequal").pack(anchor=tk.W, padx=20)
        
        split_details_frame = ttk.LabelFrame(dialog, text="Split Details", padding=10)
        split_details_frame.pack(fill=tk.X, padx=10, pady=10)
        
        split_entries = {}
        
        def update_split_details(*args):
            for widget in split_details_frame.winfo_children():
                widget.destroy()
            split_entries.clear()
            
            current_participants = [m.user for m in group.members if participant_vars.get(m.user, tk.BooleanVar()).get()]
            
            if not current_participants:
                ttk.Label(split_details_frame, text="Select participants first!", foreground="red").pack()
                return
            
            split_type = split_var.get()
            
            if split_type == "Equal":
                ttk.Label(split_details_frame, text="Each participant pays equally").pack()
            
            elif split_type == "Percentage":
                ttk.Label(split_details_frame, text="Enter percentage for each participant (must add to 100%):").pack()
                for participant in current_participants:
                    ttk.Label(split_details_frame, text=f"{participant.name} (%):").pack(anchor=tk.W, padx=20)
                    entry = ttk.Entry(split_details_frame, width=15)
                    entry.pack(anchor=tk.W, padx=40)
                    split_entries[participant] = entry
                
                ttk.Label(split_details_frame, text="Total percentage should be 100%", foreground="blue").pack(pady=5)
            
            elif split_type == "Unequal":
                try:
                    total_amount = Decimal(amount_entry.get())
                    ttk.Label(split_details_frame, text=f"Enter amount for each participant (Total: ${total_amount:.2f}):").pack()
                    for participant in current_participants:
                        ttk.Label(split_details_frame, text=f"{participant.name} ($):").pack(anchor=tk.W, padx=20)
                        entry = ttk.Entry(split_details_frame, width=15)
                        entry.pack(anchor=tk.W, padx=40)
                        split_entries[participant] = entry
                    
                    ttk.Label(split_details_frame, text="Amounts should add up to the total", foreground="blue").pack(pady=5)
                except:
                    ttk.Label(split_details_frame, text="Enter valid total amount first!", foreground="red").pack()
        
        split_var.trace("w", update_split_details)
        for var in participant_vars.values():
            var.trace("w", update_split_details)
        
        def add_expense():
            desc = desc_entry.get()
            amount_str = amount_entry.get()
            payer_name = payer_var.get()
            
            # Use validation service
            result = self.validator.validate_expense_input(desc, amount_str, payer_name, selected_participants)
            if not result.is_success():
                messagebox.showerror("Validation Error", result.message)
                return
            
            amount = result.data
            payer = next(m.user for m in group.members if m.user.name == payer_name)
            split_type = split_var.get()
            
            if split_type == "Equal":
                split_method = EqualSplit()
            
            elif split_type == "Percentage":
                split_method = PercentageSplit()
                percentages = {}
                
                try:
                    for participant, entry in split_entries.items():
                        pct_str = entry.get().strip()
                        if not pct_str:
                            messagebox.showerror("Percentage Error", f"❌ Percentage for {participant.name} is empty!")
                            return
                        pct = float(pct_str)
                        if pct < 0:
                            messagebox.showerror("Percentage Error", "❌ Percentage cannot be negative!")
                            return
                        percentages[participant] = pct
                    
                    result = split_method.set_percentages(percentages)
                    if not result.is_success():
                        messagebox.showerror("Percentage Error", result.message)
                        return
                
                except ValueError:
                    messagebox.showerror("Percentage Error", "❌ Invalid percentage value!")
                    return
            
            elif split_type == "Unequal":
                split_method = UnequalSplit()
                amounts = {}
                
                try:
                    for participant, entry in split_entries.items():
                        amt_str = entry.get().strip()
                        if not amt_str:
                            messagebox.showerror("Amount Error", f"❌ Amount for {participant.name} is empty!")
                            return
                        amt = Decimal(amt_str)
                        if amt < 0:
                            messagebox.showerror("Amount Error", "❌ Amount cannot be negative!")
                            return
                        amounts[participant] = amt
                    
                    result = split_method.set_custom_amounts(amounts, amount)
                    if not result.is_success():
                        messagebox.showerror("Amount Error", result.message)
                        return
                
                except:
                    messagebox.showerror("Amount Error", "❌ Invalid amount value!")
                    return
            
            expense = Expense(group, desc, amount, payer, selected_participants, split_method)
            group.add_expense(expense)
            
            output = f"✅ Expense added successfully!\n{expense.get_details()}"
            self.print_output(output)
            messagebox.showinfo("Success", "✅ Expense added successfully!")
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=15)
        ttk.Button(button_frame, text="Add Expense", command=add_expense).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def show_group_debts(self, group):
        """Display simplified debts and allow settlement"""
        simplified = group.get_simplified_debts()
        output = "💳 SIMPLIFIED DEBTS:\n"
        if simplified:
            for (debtor_name, creditor_name), amount in simplified.items():
                output += f"\n{debtor_name} owes {creditor_name}: ${amount:.2f}"
        else:
            output += "\n✅ All debts are settled!"
        
        self.print_output(output)
        
        if simplified:
            self.show_settle_debt_dialog(group, simplified)
    
    def show_settle_debt_dialog(self, group, simplified):
        """Dialog to settle debts"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Settle Debt")
        dialog.geometry("450x350")
        
        ttk.Label(dialog, text="Select debt to settle:", font=("Arial", 11, "bold")).pack(pady=10)
        
        debts_list = list(simplified.items())
        debt_var = tk.StringVar()
        
        # Create frame for radio buttons with scrollbar
        debt_frame = ttk.Frame(dialog)
        debt_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for idx, ((user1, user2), amount) in enumerate(debts_list):
            ttk.Radiobutton(debt_frame, text=f"{user1} owes {user2}: ${amount:.2f}", 
                          variable=debt_var, value=str(idx)).pack(anchor=tk.W, pady=3)
        
        # Payment amount section
        ttk.Label(dialog, text="Payment Amount ($):", font=("Arial", 10)).pack(pady=10)
        amount_entry = ttk.Entry(dialog, width=20)
        amount_entry.pack()
        
        def settle():
            """Process debt settlement"""
            if not debt_var.get():
                messagebox.showerror("Error", "❌ Select a debt to settle!")
                return
            
            try:
                payment = Decimal(amount_entry.get())
                if payment <= 0:
                    messagebox.showerror("Error", "❌ Payment amount must be greater than 0!")
                    return
            except:
                messagebox.showerror("Error", "❌ Invalid payment amount!")
                return
            
            debt_idx = int(debt_var.get())
            (debtor_name, creditor_name), max_amount = debts_list[debt_idx]
            
            if payment > max_amount:
                messagebox.showerror("Error", f"❌ Payment cannot exceed ${max_amount:.2f}!")
                return
            
            # Find debtor and creditor users
            debtor = next(m.user for m in group.members if m.user.name == debtor_name)
            creditor = next(m.user for m in group.members if m.user.name == creditor_name)
            
            # Settle the debt
            group.debt_ledger.settle_debt(debtor, creditor, payment)
            
            # Output result
            self.print_output(f"✅ Payment of ${payment:.2f} recorded!\n{debtor_name} paid {creditor_name}")
            messagebox.showinfo("Success", f"✅ Payment settled successfully!")
            dialog.destroy()
        
        # Buttons frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="✅ Settle", command=settle).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def show_group_expenses(self, group):
        """Display all expenses in group"""
        if not group.expenses:
            output = "❌ No expenses in this group"
        else:
            output = "📋 EXPENSES IN GROUP:\n"
            for idx, exp in enumerate(group.expenses, 1):
                output += f"\n{idx}. {exp.get_details()}\n"
        
        self.print_output(output)
    
    def show_friends(self):
        """Show friends and allow transactions"""
        if not self.current_user.friends:
            self.print_output("❌ No friends yet!")
            return
        
        output = "👥 YOUR FRIENDS:\n"
        for idx, friend in enumerate(self.current_user.friends, 1):
            output += f"\n{idx}. {friend.name} ({friend.email})"
        
        self.print_output(output)
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Friend")
        dialog.geometry("400x250")
        
        ttk.Label(dialog, text="Select a friend to view/add expenses:", font=("Arial", 10, "bold")).pack(pady=10)
        friend_var = tk.StringVar()
        friend_combo = ttk.Combobox(dialog, textvariable=friend_var,
                                   values=[f"{i}. {f.name}" for i, f in enumerate(self.current_user.friends, 1)],
                                   state="readonly", width=40)
        friend_combo.pack(pady=10, padx=10, fill=tk.X)
        
        def open_friend():
            if not friend_var.get():
                messagebox.showerror("Error", "❌ Select a friend!")
                return
            idx = int(friend_var.get().split(".")[0]) - 1
            friend = self.current_user.friends[idx]
            
            # Find or create friend group
            friend_group = None
            for group in self.groups:
                if group.is_friend_group and friend in [m.user for m in group.members]:
                    friend_group = group
                    break
            
            if not friend_group:
                friend_group = Group(f"{self.current_user.name} + {friend.name}", "Friend Group", 
                                    self.current_user, is_friend_group=True)
                friend_group.add_member(friend)
                self.groups.append(friend_group)
                self.print_output(f"✅ Friend group created with {friend.name}!")
            
            self.show_group_menu(friend_group)
            dialog.destroy()
        
        ttk.Button(dialog, text="Open", command=open_friend).pack(pady=10)
    
    def show_all_debts(self):
        """Display all active debts across all groups"""
        output = "💳 ALL YOUR DEBTS:\n"
        all_debts = []
        for group in self.groups:
            for debt in group.debt_ledger.debts:
                if debt.status == DebtStatus.ACTIVE:
                    all_debts.append(debt.get_details())
        
        if all_debts:
            for idx, debt in enumerate(all_debts, 1):
                output += f"\n{idx}. {debt}"
        else:
            output += "\n✅ You have no active debts!"
        
        self.print_output(output)

# ==================== MAIN ====================
if __name__ == "__main__":
    root = tk.Tk()
    app = SplitSmartUI(root)
    root.mainloop()