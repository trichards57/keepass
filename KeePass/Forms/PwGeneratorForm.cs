/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2023 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

using KeePass.App;
using KeePass.Resources;
using KeePass.UI;
using KeePass.Util;

using KeePassLib;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KeePass.Forms
{
	public partial class PwGeneratorForm : Form
	{
		private const int MaxPreviewPasswords = 30;

		private PwProfile m_optInitial = null;
		private PwProfile m_optSelected = new PwProfile();

		private readonly string CustomMeta = "(" + KPRes.Custom + ")";
		private readonly string DeriveFromPrevious = "(" + KPRes.GenPwBasedOnPrevious + ")";
		private readonly string AutoGeneratedMeta = "(" + KPRes.AutoGeneratedPasswordSettings + ")";

		private readonly string NoCustomAlgo = "(" + KPRes.None + ")";

		private uint m_uBlockUIUpdate = 0;
		private bool m_bCanAccept = true;
		// private bool m_bForceInTaskbar = false;

		private string m_strAdvControlText = string.Empty;

		private Dictionary<CustomPwGenerator, string> m_dictCustomOptions =
			new Dictionary<CustomPwGenerator, string>();

		public PwProfile SelectedProfile
		{
			get { return m_optSelected; }
		}

		/// <summary>
		/// Initialize this password generator form instance.
		/// </summary>
		/// <param name="pwInitial">Initial options (may be <c>null</c>).</param>
		public void InitEx(PwProfile pwInitial, bool bCanAccept, bool bForceInTaskbar)
		{
			m_optInitial = pwInitial;
			m_bCanAccept = bCanAccept;

			// m_bForceInTaskbar = bForceInTaskbar;
			// Set ShowInTaskbar immediately, not later, otherwise the form
			// can disappear:
			// https://sourceforge.net/p/keepass/discussion/329220/thread/c95b5644/
			if(bForceInTaskbar) this.ShowInTaskbar = true;
		}

		public PwGeneratorForm()
		{
			InitializeComponent();
			GlobalWindowManager.InitializeForm(this);
		}

		private void OnFormLoad(object sender, EventArgs e)
		{
			// Can be invoked by tray command; don't use CenterParent
			Debug.Assert(this.StartPosition == FormStartPosition.CenterScreen);

			++m_uBlockUIUpdate;

			GlobalWindowManager.AddWindow(this);

			m_strAdvControlText = m_tabAdvanced.Text;

			BannerFactory.CreateBannerEx(this, m_bannerImage,
				Properties.Resources.B48x48_KGPG_Gen, KPRes.PasswordOptions,
				KPRes.PasswordOptionsDesc);
			this.Icon = AppIcons.Default;

			UIUtil.SetButtonImage(m_btnProfileAdd,
				Properties.Resources.B16x16_FileSaveAs, false);
			UIUtil.SetButtonImage(m_btnProfileRemove,
				Properties.Resources.B16x16_EditDelete, true);

			FontUtil.AssignDefaultBold(m_rbStandardCharSet);
			FontUtil.AssignDefaultBold(m_rbPattern);
			FontUtil.AssignDefaultBold(m_rbCustom);
			FontUtil.AssignDefaultMono(m_tbPreview, true);

			UIUtil.ConfigureToolTip(m_ttMain);
			UIUtil.SetToolTip(m_ttMain, m_btnProfileAdd, KPRes.ProfileSaveDesc, false);
			UIUtil.SetToolTip(m_ttMain, m_btnProfileRemove, KPRes.ProfileDeleteDesc, false);
			UIUtil.SetToolTip(m_ttMain, m_btnCustomOpt, KPRes.Options, true);

			AccessibilityEx.SetName(m_btnProfileAdd, KPRes.ProfileSave);
			AccessibilityEx.SetName(m_btnProfileRemove, KPRes.ProfileDelete);

			using(RtlAwareResizeScope r = new RtlAwareResizeScope(
				m_cbUpperCase, m_cbLowerCase, m_cbDigits, m_cbMinus,
				m_cbUnderline, m_cbSpace, m_cbSpecial, m_cbBrackets,
				m_cbLatin1S, m_cbNoRepeat, m_cbExcludeLookAlike,
				m_lblExcludeChars, m_lblSecRedInfo))
			{
				m_cbUpperCase.Text += " (A, B, C, ...)";
				m_cbLowerCase.Text += " (a, b, c, ...)";
				m_cbDigits.Text += " (0, 1, 2, ...)";
				m_cbMinus.Text += " (-)";
				m_cbUnderline.Text += " (_)";
				m_cbSpace.Text += " ( )";
				m_cbSpecial.Text += @" (!, $, %, &&, ...)";
				m_cbBrackets.Text += @" ([, ], {, }, (, ), <, >)";
				m_cbLatin1S.Text += " (\u00C4, \u00B5, \u00B6, ...)";
				m_cbNoRepeat.Text += " *";
				m_cbExcludeLookAlike.Text += " (O0, Il1|) *";
				m_lblExcludeChars.Text += " *";
				m_lblSecRedInfo.Text = "* " + m_lblSecRedInfo.Text;
			}

			SetCharSetTT(m_cbUpperCase, PwCharSet.UpperCase, 2);
			SetCharSetTT(m_cbLowerCase, PwCharSet.LowerCase, 2);
			SetCharSetTT(m_cbDigits, PwCharSet.Digits, 2);
			SetCharSetTT(m_cbSpecial, PwCharSet.Special, 2);
			SetCharSetTT(m_cbLatin1S, PwCharSet.Latin1S, 4);

			m_cmbCustomAlgo.Items.Add(NoCustomAlgo);
			foreach(CustomPwGenerator pwg in Program.PwGeneratorPool)
			{
				m_cmbCustomAlgo.Items.Add(pwg.Name);
			}
			SelectCustomGenerator((m_optInitial != null) ?
				m_optInitial.CustomAlgorithmUuid : null, null);
			if(m_optInitial != null)
			{
				CustomPwGenerator pwg = GetPwGenerator();
				if(pwg != null) m_dictCustomOptions[pwg] = m_optInitial.CustomAlgorithmOptions;
			}

			m_cmbProfiles.Items.Add(CustomMeta);

			if(m_optInitial != null)
			{
				m_cmbProfiles.Items.Add(DeriveFromPrevious);
				SetGenerationOptions(m_optInitial);
			}

			m_cmbProfiles.Items.Add(AutoGeneratedMeta);

			m_cmbProfiles.SelectedIndex = ((m_optInitial == null) ? 0 : 1);

			foreach(PwProfile ppw in PwGeneratorUtil.GetAllProfiles(true))
			{
				m_cmbProfiles.Items.Add(ppw.Name);

				if((ppw.GeneratorType == PasswordGeneratorType.Custom) &&
					!string.IsNullOrEmpty(ppw.CustomAlgorithmUuid))
				{
					CustomPwGenerator pwg = Program.PwGeneratorPool.Find(new
						PwUuid(Convert.FromBase64String(ppw.CustomAlgorithmUuid)));
					if(pwg != null) m_dictCustomOptions[pwg] = ppw.CustomAlgorithmOptions;
				}
			}
	
			if(m_optInitial == null)
			{
				// int nIndex = m_cmbProfiles.FindString(Program.Config.PasswordGenerator.LastUsedProfile.Name);
				// if(nIndex >= 0) m_cmbProfiles.SelectedIndex = nIndex;
				SetGenerationOptions(Program.Config.PasswordGenerator.LastUsedProfile);
			}

			if(!m_bCanAccept)
			{
				m_tabPreview.Text = KPRes.Generate;
				m_lblPreview.Text = KPRes.GeneratedPasswords + ":";

				m_btnOK.Visible = false;
				m_btnCancel.Text = KPRes.Close;
			}

			// Debug.Assert(!this.ShowInTaskbar);
			// if(m_bForceInTaskbar) this.ShowInTaskbar = true;

			m_rbStandardCharSet.CheckedChanged += this.UpdateUIProc;
			m_rbPattern.CheckedChanged += this.UpdateUIProc;
			m_rbCustom.CheckedChanged += this.UpdateUIProc;
			m_numGenChars.ValueChanged += this.UpdateUIProc;
			m_cbUpperCase.CheckedChanged += this.UpdateUIProc;
			m_cbLowerCase.CheckedChanged += this.UpdateUIProc;
			m_cbDigits.CheckedChanged += this.UpdateUIProc;
			m_cbMinus.CheckedChanged += this.UpdateUIProc;
			m_cbUnderline.CheckedChanged += this.UpdateUIProc;
			m_cbSpace.CheckedChanged += this.UpdateUIProc;
			m_cbSpecial.CheckedChanged += this.UpdateUIProc;
			m_cbBrackets.CheckedChanged += this.UpdateUIProc;
			m_cbLatin1S.CheckedChanged += this.UpdateUIProc;
			m_tbCustomChars.TextChanged += this.UpdateUIProc;
			m_tbPattern.TextChanged += this.UpdateUIProc;
			m_cbPatternPermute.CheckedChanged += this.UpdateUIProc;
			m_cmbCustomAlgo.SelectedIndexChanged += this.UpdateUIProc;
			m_cbEntropy.CheckedChanged += this.UpdateUIProc;
			m_cbNoRepeat.CheckedChanged += this.UpdateUIProc;
			m_cbExcludeLookAlike.CheckedChanged += this.UpdateUIProc;
			m_tbExcludeChars.TextChanged += this.UpdateUIProc;

			--m_uBlockUIUpdate;
			EnableControlsEx(false);
		}

		private void SetCharSetTT(CheckBox cb, string strCharSet, int cLines)
		{
			int ccLine = (int)Math.Ceiling((double)strCharSet.Length / cLines);
			if(ccLine <= 1) { Debug.Assert(false); ccLine = int.MaxValue; }

			StringBuilder sb = new StringBuilder();
			for(int i = 0; i < strCharSet.Length; ++i)
			{
				if(((i % ccLine) == 0) && (i != 0))
					sb.Append(MessageService.NewLine);
				sb.Append(strCharSet[i]);
			}

			UIUtil.SetToolTip(m_ttMain, cb, sb.ToString(), false);
		}

		private void EnableControlsEx(bool bSwitchToCustomProfile)
		{
			if(m_uBlockUIUpdate != 0) return;
			++m_uBlockUIUpdate;

			if(bSwitchToCustomProfile)
				m_cmbProfiles.SelectedIndex = 0;

			string strProfile = m_cmbProfiles.Text;
			m_btnProfileRemove.Enabled = ((strProfile != CustomMeta) &&
				(strProfile != DeriveFromPrevious) && (strProfile != AutoGeneratedMeta) &&
				!PwGeneratorUtil.IsBuiltInProfile(strProfile));

			UIUtil.SetEnabledFast(m_rbStandardCharSet.Checked, m_lblNumGenChars,
				m_numGenChars, m_cbUpperCase, m_cbLowerCase, m_cbDigits,
				m_cbMinus, m_cbUnderline, m_cbSpace, m_cbSpecial, m_cbBrackets,
				m_cbLatin1S, m_lblCustomChars, m_tbCustomChars);
			UIUtil.SetEnabledFast(m_rbPattern.Checked, m_tbPattern, m_cbPatternPermute);

			m_cmbCustomAlgo.Enabled = m_rbCustom.Checked;
			if(!m_rbCustom.Checked) m_btnCustomOpt.Enabled = false;
			else
			{
				CustomPwGenerator pwg = GetPwGenerator();
				if(pwg != null) m_btnCustomOpt.Enabled = pwg.SupportsOptions;
				else m_btnCustomOpt.Enabled = false;
			}

			m_tabAdvanced.Text = ((m_cbNoRepeat.Checked || m_cbExcludeLookAlike.Checked ||
				(m_tbExcludeChars.Text.Length != 0)) ? (m_strAdvControlText + " (!)") :
				m_strAdvControlText);

			--m_uBlockUIUpdate;
		}

		private void OnFormClosed(object sender, FormClosedEventArgs e)
		{
			Debug.Assert(m_uBlockUIUpdate == 0);

			Program.Config.PasswordGenerator.LastUsedProfile = GetGenerationOptions();

			// if(m_bForceInTaskbar) this.ShowInTaskbar = false;

			GlobalWindowManager.RemoveWindow(this);
		}

		private void OnBtnOK(object sender, EventArgs e)
		{
			m_optSelected = GetGenerationOptions();
		}

		private void OnBtnCancel(object sender, EventArgs e)
		{
		}

		private PwProfile GetGenerationOptions()
		{
			PwProfile opt = new PwProfile();

			opt.Name = m_cmbProfiles.Text;

			if(m_rbStandardCharSet.Checked)
				opt.GeneratorType = PasswordGeneratorType.CharSet;
			else if(m_rbPattern.Checked)
				opt.GeneratorType = PasswordGeneratorType.Pattern;
			else if(m_rbCustom.Checked)
				opt.GeneratorType = PasswordGeneratorType.Custom;

			opt.Length = (uint)m_numGenChars.Value;

			opt.CharSet = new PwCharSet();

			if(m_cbUpperCase.Checked) opt.CharSet.Add(PwCharSet.UpperCase);
			if(m_cbLowerCase.Checked) opt.CharSet.Add(PwCharSet.LowerCase);
			if(m_cbDigits.Checked) opt.CharSet.Add(PwCharSet.Digits);
			if(m_cbSpecial.Checked) opt.CharSet.Add(PwCharSet.Special);
			if(m_cbLatin1S.Checked) opt.CharSet.Add(PwCharSet.Latin1S);
			if(m_cbMinus.Checked) opt.CharSet.Add('-');
			if(m_cbUnderline.Checked) opt.CharSet.Add('_');
			if(m_cbSpace.Checked) opt.CharSet.Add(' ');
			if(m_cbBrackets.Checked) opt.CharSet.Add(PwCharSet.Brackets);

			opt.CharSet.Add(m_tbCustomChars.Text);

			opt.Pattern = m_tbPattern.Text;
			opt.PatternPermutePassword = m_cbPatternPermute.Checked;

			CustomPwGenerator pwg = GetPwGenerator();
			opt.CustomAlgorithmUuid = ((pwg != null) ? Convert.ToBase64String(
				pwg.Uuid.UuidBytes) : string.Empty);
			if((pwg != null) && m_dictCustomOptions.ContainsKey(pwg))
				opt.CustomAlgorithmOptions = (m_dictCustomOptions[pwg] ?? string.Empty);
			else opt.CustomAlgorithmOptions = string.Empty;

			opt.CollectUserEntropy = m_cbEntropy.Checked;

			opt.NoRepeatingCharacters = m_cbNoRepeat.Checked;
			opt.ExcludeLookAlike = m_cbExcludeLookAlike.Checked;
			opt.ExcludeCharacters = m_tbExcludeChars.Text;

			return opt;
		}

		private void SetGenerationOptions(PwProfile opt)
		{
			++m_uBlockUIUpdate;

			m_rbStandardCharSet.Checked = (opt.GeneratorType == PasswordGeneratorType.CharSet);
			m_rbPattern.Checked = (opt.GeneratorType == PasswordGeneratorType.Pattern);
			m_rbCustom.Checked = (opt.GeneratorType == PasswordGeneratorType.Custom);

			m_numGenChars.Value = opt.Length;

			PwCharSet pcs = new PwCharSet(opt.CharSet.ToString());

			m_cbUpperCase.Checked = pcs.RemoveIfAllExist(PwCharSet.UpperCase);
			m_cbLowerCase.Checked = pcs.RemoveIfAllExist(PwCharSet.LowerCase);
			m_cbDigits.Checked = pcs.RemoveIfAllExist(PwCharSet.Digits);
			m_cbSpecial.Checked = pcs.RemoveIfAllExist(PwCharSet.Special);
			m_cbLatin1S.Checked = pcs.RemoveIfAllExist(PwCharSet.Latin1S);
			m_cbMinus.Checked = pcs.RemoveIfAllExist("-");
			m_cbUnderline.Checked = pcs.RemoveIfAllExist("_");
			m_cbSpace.Checked = pcs.RemoveIfAllExist(" ");
			m_cbBrackets.Checked = pcs.RemoveIfAllExist(PwCharSet.Brackets);

			m_tbCustomChars.Text = pcs.ToString();

			m_tbPattern.Text = opt.Pattern;
			m_cbPatternPermute.Checked = opt.PatternPermutePassword;

			SelectCustomGenerator(opt.CustomAlgorithmUuid, opt.CustomAlgorithmOptions);

			m_cbEntropy.Checked = opt.CollectUserEntropy;

			m_cbNoRepeat.Checked = opt.NoRepeatingCharacters;
			m_cbExcludeLookAlike.Checked = opt.ExcludeLookAlike;
			m_tbExcludeChars.Text = opt.ExcludeCharacters;

			--m_uBlockUIUpdate;
		}

		private void UpdateUIProc(object sender, EventArgs e)
		{
			EnableControlsEx(true);
		}

		private void OnProfilesSelectedIndexChanged(object sender, EventArgs e)
		{
			if(m_uBlockUIUpdate != 0) return;

			string strProfile = m_cmbProfiles.Text;

			if(strProfile == CustomMeta) { } // Switch to custom -> nothing to do
			else if(strProfile == DeriveFromPrevious)
				SetGenerationOptions(m_optInitial);
			else if(strProfile == AutoGeneratedMeta)
				SetGenerationOptions(Program.Config.PasswordGenerator.AutoGeneratedPasswordsProfile);
			else
			{
				foreach(PwProfile pwgo in PwGeneratorUtil.GetAllProfiles(false))
				{
					if(pwgo.Name == strProfile)
					{
						SetGenerationOptions(pwgo);
						break;
					}
				}
			}

			EnableControlsEx(false);
		}

		private void OnBtnProfileSave(object sender, EventArgs e)
		{
			List<string> lNames = new List<string>();
			lNames.Add(AutoGeneratedMeta);
			foreach(PwProfile pwExisting in Program.Config.PasswordGenerator.UserProfiles)
				lNames.Add(pwExisting.Name);

			SingleLineEditForm slef = new SingleLineEditForm();
			slef.InitEx(KPRes.ProfileSave, KPRes.ProfileSaveDesc,
				KPRes.ProfileSavePrompt, Properties.Resources.B48x48_KGPG_Gen,
				string.Empty, lNames.ToArray());

			if(slef.ShowDialog() == DialogResult.OK)
			{
				string strProfile = slef.ResultString;

				PwProfile pwCurrent = GetGenerationOptions();
				pwCurrent.Name = strProfile;

				if(strProfile.Equals(CustomMeta) || strProfile.Equals(DeriveFromPrevious) ||
					(strProfile.Length == 0) || PwGeneratorUtil.IsBuiltInProfile(strProfile))
				{
					MessageService.ShowWarning(KPRes.FieldNameInvalid);
				}
				else if(strProfile == AutoGeneratedMeta)
				{
					pwCurrent.Name = string.Empty;
					Program.Config.PasswordGenerator.AutoGeneratedPasswordsProfile = pwCurrent;
					m_cmbProfiles.SelectedIndex = m_cmbProfiles.FindString(AutoGeneratedMeta);
				}
				else
				{
					List<PwProfile> lUser = Program.Config.PasswordGenerator.UserProfiles;

					bool bExists = false;
					for(int i = 0; i < lUser.Count; ++i)
					{
						if(lUser[i].Name.Equals(strProfile, StrUtil.CaseIgnoreCmp))
						{
							lUser[i] = pwCurrent;

							for(int j = 0; j < m_cmbProfiles.Items.Count; ++j)
							{
								if(m_cmbProfiles.Items[j].ToString().Equals(strProfile,
									StrUtil.CaseIgnoreCmp))
								{
									++m_uBlockUIUpdate;
									m_cmbProfiles.Items[j] = strProfile; // Fix case
									--m_uBlockUIUpdate;
									m_cmbProfiles.SelectedIndex = j;
									bExists = true;
									break;
								}
							}

							break;
						}
					}

					if(!bExists)
					{
						++m_uBlockUIUpdate;

						List<PwProfile> lAll = PwGeneratorUtil.GetAllProfiles(false);
						for(int c = 0; c < lAll.Count; ++c)
							m_cmbProfiles.Items.RemoveAt(m_cmbProfiles.Items.Count - 1);

						lUser.Add(pwCurrent);

						int iNewSel = 0;
						foreach(PwProfile pwAdd in PwGeneratorUtil.GetAllProfiles(true))
						{
							m_cmbProfiles.Items.Add(pwAdd.Name);
							if(pwAdd.Name == strProfile)
								iNewSel = m_cmbProfiles.Items.Count - 1;
						}

						--m_uBlockUIUpdate;
						m_cmbProfiles.SelectedIndex = iNewSel;
					}
				}
			}
			UIUtil.DestroyForm(slef);

			EnableControlsEx(false);
		}

		private void OnBtnProfileRemove(object sender, EventArgs e)
		{
			string strProfile = m_cmbProfiles.Text;

			if((strProfile == CustomMeta) || (strProfile == DeriveFromPrevious) ||
				(strProfile == AutoGeneratedMeta) || PwGeneratorUtil.IsBuiltInProfile(strProfile))
				return;

			m_cmbProfiles.SelectedIndex = 0;
			for(int i = 0; i < m_cmbProfiles.Items.Count; ++i)
			{
				if(strProfile == m_cmbProfiles.Items[i].ToString())
				{
					m_cmbProfiles.Items.RemoveAt(i);

					List<PwProfile> lUser = Program.Config.PasswordGenerator.UserProfiles;
					for(int j = 0; j < lUser.Count; ++j)
					{
						if(lUser[j].Name == strProfile)
						{
							lUser.RemoveAt(j);
							break;
						}
					}

					break;
				}
			}
		}

		private void OnBtnHelp(object sender, EventArgs e)
		{
			AppHelp.ShowHelp(AppDefs.HelpTopics.PwGenerator, null);
		}

		private void OnTabMainSelectedIndexChanged(object sender, EventArgs e)
		{
			if(m_uBlockUIUpdate != 0) return;

			if(m_tabMain.SelectedTab == m_tabPreview)
				GeneratePreviewPasswords();
		}

		private void GeneratePreviewPasswords()
		{
			this.UseWaitCursor = true;

			m_pbPreview.Value = 0;
			m_tbPreview.Text = string.Empty;

			PwProfile prf = GetGenerationOptions();

			int n = MaxPreviewPasswords;
			if((prf.GeneratorType == PasswordGeneratorType.Custom) &&
				string.IsNullOrEmpty(prf.CustomAlgorithmUuid))
				n = 0;

			byte[] pbUserEntropy = null;
			if(!m_bCanAccept && (n != 0))
				pbUserEntropy = EntropyForm.CollectEntropyIfEnabled(prf);

			PwEntry peContext = new PwEntry(true, true);
			MainForm mf = Program.MainForm;
			PwDatabase pdContext = ((mf != null) ? mf.ActiveDatabase : null);

			StringBuilder sbList = new StringBuilder();
			bool bAcceptAlways = false;

			for(int i = 0; i < n; ++i)
			{
				Application.DoEvents();

				string strError;
				ProtectedString psNew = PwGeneratorUtil.GenerateAcceptable(
					prf, pbUserEntropy, peContext, pdContext, false,
					ref bAcceptAlways, out strError);

				if(!string.IsNullOrEmpty(strError))
				{
					sbList.Remove(0, sbList.Length);
					sbList.AppendLine(strError);
					break;
				}

				sbList.AppendLine(psNew.ReadString());
				m_pbPreview.Value = (100 * (i + 1)) / n;
			}

			m_pbPreview.Value = 100; // In case of error or n = 0
			UIUtil.SetMultilineText(m_tbPreview, sbList.ToString());

			this.UseWaitCursor = false;
		}

		private CustomPwGenerator GetPwGenerator()
		{
			string strAlgo = (m_cmbCustomAlgo.SelectedItem as string);
			if(strAlgo == null) return null;

			return Program.PwGeneratorPool.Find(strAlgo);
		}

		private void SelectCustomGenerator(string strUuid, string strCustomOptions)
		{
			int iSel = 0;
			try
			{
				if(string.IsNullOrEmpty(strUuid)) return;

				PwUuid uuid = new PwUuid(Convert.FromBase64String(strUuid));
				CustomPwGenerator pwg = Program.PwGeneratorPool.Find(uuid);
				if(pwg == null) return;

				for(int i = 0; i < m_cmbCustomAlgo.Items.Count; ++i)
				{
					if((m_cmbCustomAlgo.Items[i] as string) == pwg.Name)
					{
						iSel = i;

						if(strCustomOptions != null)
							m_dictCustomOptions[pwg] = strCustomOptions;

						break;
					}
				}
			}
			finally { m_cmbCustomAlgo.SelectedIndex = iSel; }
		}

		private void OnBtnCustomOpt(object sender, EventArgs e)
		{
			CustomPwGenerator pwg = GetPwGenerator();
			if(pwg == null) { Debug.Assert(false); return; }
			if(!pwg.SupportsOptions) { Debug.Assert(false); return; }

			string strCurOpt = string.Empty;
			if(m_dictCustomOptions.ContainsKey(pwg))
				strCurOpt = (m_dictCustomOptions[pwg] ?? string.Empty);

			m_dictCustomOptions[pwg] = pwg.GetOptions(strCurOpt);
		}
	}
}
